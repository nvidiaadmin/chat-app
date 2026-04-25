#!/usr/bin/env python3
"""
Peer-to-peer terminal chat over Tailscale.
Uses asyncio for networking and curses for the UI.
- New message from peer replaces the previous one (only latest shown).
- Shortcut: Ctrl+L clears the displayed message and shows the prompt.
"""

import asyncio
import argparse
import curses
import getpass
import hashlib
import json
import queue
import shlex
import sys
import threading
import urllib.error
import urllib.request
from typing import Any
# Message protocol: UTF-8 lines (newline-terminated)
ENCODING = "utf-8"
DEFAULT_PORT = 8765
DEFAULT_SERVER = "https://webserver-pkrd.onrender.com"
ALLOWED_USERS = {"A", "B"}

# Keyboard shortcut to clear message and show prompt
CLEAR_MESSAGE_KEY = ord("l") & 0x1F  # Ctrl+L


def parse_args():
    parser = argparse.ArgumentParser(description="Terminal chat utility")
    parser.add_argument(
        "--server",
        default=DEFAULT_SERVER,
        help=f"Base URL of message server (default {DEFAULT_SERVER})",
    )
    parser.add_argument("--user", choices=sorted(ALLOWED_USERS), required=True)
    return parser.parse_args()


def other_user(user: str) -> str:
    return "B" if user == "A" else "A"


def post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req) as response:
            response_data = response.read().decode("utf-8")
            return json.loads(response_data)
    except urllib.error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Server returned HTTP {exc.code}: {details}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Cannot connect to server: {exc.reason}") from exc


def handle_rest_send(base_url: str, user: str, message: str) -> int:
    payload = {"from_user": user, "to_user": other_user(user), "message": message}
    result = post_json(f"{base_url}/messages", payload)
    clear_terminal()
    print(f"message sent at {result.get('sent_at')}")
    return 0


def fetch_rest_messages(base_url: str, user: str, read_key_hash: str) -> list[dict[str, Any]]:
    result = post_json(
        f"{base_url}/messages/read",
        {"user": user, "read_key_hash": read_key_hash},
    )
    messages = result.get("messages", [])
    if not isinstance(messages, list):
        return []
    return messages


def clear_terminal() -> None:
    # ANSI clear screen + move cursor to top-left.
    print("\033[2J\033[H", end="")


def handle_rest_read(base_url: str, user: str) -> int:
    try:
        entered = getpass.getpass("Enter read passphrase: ")
    except EOFError:
        print("Authentication input cancelled.")
        return 1
    entered = entered.strip()
    if not entered:
        print("Authentication failed.")
        return 1

    read_key_hash = hashlib.sha256(entered.encode("utf-8")).hexdigest()
    messages = fetch_rest_messages(base_url, user, read_key_hash)
    idx = 0
    while True:
        if idx >= len(messages):
            clear_terminal()
            print("No pending messages to show.")
            return 0

        msg = messages[idx]
        clear_terminal()
        print(f"[{msg.get('sent_at')}] {msg.get('from')}: {msg.get('message')}")
        try:
            choice = input("\nPress 'n' for next message, 'q' to return: ").strip().lower()
        except EOFError:
            return 0
        if choice == "n":
            idx += 1
            continue
        if choice == "q":
            return 0


def run_p2p_session(listen_port: int | None, connect_host: str | None, connect_port: int) -> int:
    incoming = queue.Queue()
    outgoing = queue.Queue()

    if listen_port is not None:
        status = (
            f"Listening on port {listen_port} (Tailscale). "
            "Start peer with /connect <this-machine-tailscale-name> [port]"
        )
        thread = threading.Thread(
            target=_run_server_loop,
            args=(listen_port, incoming, outgoing),
            daemon=True,
        )
    else:
        status = f"Connecting to {connect_host}:{connect_port}..."
        thread = threading.Thread(
            target=_run_client_loop,
            args=(connect_host, connect_port, incoming, outgoing),
            daemon=True,
        )

    thread.start()
    try:
        kind, payload = incoming.get(timeout=2.0)
        if kind == "status":
            status = payload
        elif kind == "error":
            print(payload, file=sys.stderr)
            return 1
        else:
            incoming.put((kind, payload))
    except queue.Empty:
        pass

    try:
        curses.wrapper(run_ui, incoming, outgoing, status)
    except KeyboardInterrupt:
        pass
    return 0


def print_command_help() -> None:
    print("Commands:")
    print("  /connect --listen <port>       Waiting for device to boot and enter recover mod")
    print("  /connect <host> [port]         Connect to device and enter recover mode")
    print("  /send <message>                Send flash command to device over UART")
    print("  /read                          Authenticate, then read pending messages one by one")
    print("  /help                          Show commands")
    print("  /exit                          Quit")


def command_loop(server: str, user: str) -> int:
    # print(f"User {user} ready. Server: {server}")
    print("Type /help for commands.")
    while True:
        try:
            raw = input("flash> ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            return 0

        if not raw:
            continue
        if raw == "/exit":
            return 0
        if raw == "/help":
            print_command_help()
            continue
        if raw == "/read":
            try:
                handle_rest_read(server, user)
            except RuntimeError as exc:
                print(str(exc), file=sys.stderr)
            continue
        if raw.startswith("/send "):
            message = raw[len("/send ") :].strip()
            if not message:
                print("Usage: /send <message>", file=sys.stderr)
                continue
            try:
                handle_rest_send(server, user, message)
            except RuntimeError as exc:
                print(str(exc), file=sys.stderr)
            continue
        if raw.startswith("/connect"):
            try:
                parts = shlex.split(raw)
            except ValueError as exc:
                print(f"Invalid command: {exc}", file=sys.stderr)
                continue
            if len(parts) < 2:
                print("Usage: /connect --listen <port> OR /connect <host> [port]", file=sys.stderr)
                continue
            if parts[1] == "--listen":
                if len(parts) != 3:
                    print("Usage: /connect --listen <port>", file=sys.stderr)
                    continue
                try:
                    port = int(parts[2])
                except ValueError:
                    print("Port must be an integer.", file=sys.stderr)
                    continue
                run_p2p_session(listen_port=port, connect_host=None, connect_port=DEFAULT_PORT)
                continue

            host = parts[1]
            port = DEFAULT_PORT
            if len(parts) >= 3:
                try:
                    port = int(parts[2])
                except ValueError:
                    print("Port must be an integer.", file=sys.stderr)
                    continue
            run_p2p_session(listen_port=None, connect_host=host, connect_port=port)
            continue

        print("Unknown command. Type /help for commands.", file=sys.stderr)


# --- Network (asyncio, runs in background thread) ---

class ChatProtocol:
    """Line-based protocol: one message per line."""

    def __init__(self, incoming_queue: queue.Queue, outgoing_queue: queue.Queue):
        self.incoming = incoming_queue
        self.outgoing = outgoing_queue
        self._reader = None
        self._writer = None
        self._closed = False

    def set_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self._reader = reader
        self._writer = writer

    def close(self):
        self._closed = True
        if self._writer:
            try:
                self._writer.close()
            except Exception:
                pass

    async def read_loop(self):
        if not self._reader:
            return
        buf = b""
        try:
            while not self._closed:
                chunk = await self._reader.read(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    try:
                        text = line.decode(ENCODING).strip()
                        if text:
                            self.incoming.put(("message", text))
                    except UnicodeDecodeError:
                        pass
            self.incoming.put(("closed", None))
        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            self.incoming.put(("closed", None))
        except Exception as e:
            self.incoming.put(("error", str(e)))

    async def write_loop(self):
        if not self._writer:
            return
        try:
            while not self._closed:
                try:
                    msg = self.outgoing.get_nowait()
                except queue.Empty:
                    await asyncio.sleep(0.05)
                    continue
                if msg is None:
                    break
                if not isinstance(msg, str):
                    continue
                data = (msg.strip() + "\n").encode(ENCODING)
                self._writer.write(data)
                await self._writer.drain()
        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            pass
        except Exception:
            pass
        finally:
            self.incoming.put(("closed", None))

    async def run_server(self, port: int):
        async def accept(reader, writer):
            self.set_connection(reader, writer)
            peername = writer.get_extra_info("peername", ("?", "?"))
            self.incoming.put(("status", f"Peer connected from {peername[0]}:{peername[1]}"))
            await asyncio.gather(self.read_loop(), self.write_loop())

        try:
            server = await asyncio.start_server(accept, "0.0.0.0", port)
        except OSError as e:
            if e.errno == 48:  # Address already in use
                self.incoming.put(
                    ("error", f"Port {port} is already in use. Try another port (e.g. --listen 8765).")
                )
            else:
                self.incoming.put(("error", str(e)))
            return
        self.incoming.put(("status", f"Listening on 0.0.0.0:{port} (Tailscale). Waiting for peer..."))
        async with server:
            await server.serve_forever()

    async def run_client(self, host: str, port: int):
        try:
            reader, writer = await asyncio.open_connection(host, port)
            self.set_connection(reader, writer)
            self.incoming.put(("status", f"Connected to {host}:{port}"))
            await asyncio.gather(self.read_loop(), self.write_loop())
        except Exception as e:
            self.incoming.put(("error", f"Connect failed: {e}"))


def _run_client_loop(host: str, port: int, inc: queue.Queue, out: queue.Queue):
    proto = ChatProtocol(inc, out)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(proto.run_client(host, port))
    finally:
        proto.close()
        loop.close()


def _run_server_loop(port: int, inc: queue.Queue, out: queue.Queue):
    proto = ChatProtocol(inc, out)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(proto.run_server(port))
    except Exception as e:
        inc.put(("error", str(e)))
    finally:
        proto.close()
        loop.close()


# --- Curses UI (main thread) ---

def run_ui(stdscr, incoming: queue.Queue, outgoing: queue.Queue, status_line: str):
    curses.curs_set(1)
    curses.use_default_colors()
    stdscr.timeout(50)  # 50 ms so we can poll queue

    # State
    peer_message = ""   # latest message from peer (replaced on new message)
    show_message = True # if False, we cleared it with Ctrl+L
    input_line = ""
    status = status_line
    done = False

    height, width = stdscr.getmaxyx()
    # Regions: status (row 0), message area (row 1..2), prompt (last row)
    prompt_row = height - 1
    msg_row = 1

    def redraw():
        stdscr.erase()
        # Status
        stdscr.addstr(0, 0, status[: width - 1], curses.A_BOLD)
        # Peer message (only if show_message and we have one)
        if show_message and peer_message:
            msg = peer_message[: width - 1]
            if len(peer_message) > width - 1:
                msg = msg[: width - 4] + "..."
            stdscr.addstr(msg_row, 0, msg)
        # Prompt
        prompt = "You: " + input_line
        stdscr.addstr(prompt_row, 0, prompt[: width - 1])
        stdscr.move(prompt_row, min(4 + len(input_line), width - 1))
        stdscr.refresh()

    redraw()

    while not done:
        # Drain all pending incoming (so we never skip a message)
        try:
            while True:
                kind, payload = incoming.get_nowait()
                if kind == "message":
                    peer_message = payload
                    show_message = True  # show new message
                elif kind == "status":
                    status = payload
                elif kind == "closed":
                    status = "Connection closed."
                elif kind == "error":
                    status = f"Error: {payload}"
        except queue.Empty:
            pass

        # Key
        key = stdscr.getch()
        if key == curses.ERR:
            redraw()
            continue

        if key == CLEAR_MESSAGE_KEY:
            # Shortcut: clear message and show prompt
            show_message = False
            peer_message = ""
        elif key == ord("\n") or key == ord("\r"):
            line = input_line.strip()
            input_line = ""
            if line:
                try:
                    outgoing.put_nowait(line)
                except queue.Full:
                    pass
        elif key in (curses.KEY_BACKSPACE, 127, 8):
            input_line = input_line[:-1]
        elif 32 <= key <= 126:
            input_line += chr(key)

        redraw()

    return 0


def main():
    args = parse_args()
    return command_loop(server=args.server, user=args.user)


if __name__ == "__main__":
    sys.exit(main())
