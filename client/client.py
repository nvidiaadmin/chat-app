#!/usr/bin/env python3
"""Interactive WebSocket chat client with certificate-based app authentication."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import curses
import getpass
import itertools
import queue
import ssl
import sys
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from common import (
    CertificateIdentity,
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_WS_PATH,
    ProtocolError,
    build_ws_url,
    decode_message,
    encode_message,
    load_private_key,
    sign_nonce,
)

CLEAR_MESSAGE_KEY = ord("l") & 0x1F


def clear_terminal() -> None:
    """Clear the terminal so only the current message remains visible."""

    print("\033[2J\033[H", end="", flush=True)


class RequestError(RuntimeError):
    """Raised when the server rejects a request."""


def other_user(identity: str) -> str:
    """Return the other chat identity in this fixed two-user system."""

    normalized = identity.strip().upper()
    if normalized == "A":
        return "B"
    if normalized == "B":
        return "A"
    raise ValueError("This client supports only the two configured users: A and B.")


@dataclass(frozen=True)
class ClientConfig:
    """Immutable runtime configuration for the client."""

    server_url: str
    cert_path: Path
    key_path: Path
    identity: CertificateIdentity


class SecureClientConnection:
    """Maintains one WebSocket connection and multiplexes responses/events."""

    STARTUP_TIMEOUT_SECONDS = 45

    def __init__(self, config: ClientConfig, private_key: Any) -> None:
        self._config = config
        self._private_key = private_key
        self._request_counter = itertools.count(1)
        self._response_waiters: dict[str, "queue.Queue[dict[str, Any]]"] = {}
        self._event_queue: "queue.Queue[dict[str, Any]]" = queue.Queue()
        self._hello_event = threading.Event()
        self._hello_payload: dict[str, Any] | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._websocket = None
        self._stop_requested = False
        self._startup_error: str | None = None

    @property
    def event_queue(self) -> "queue.Queue[dict[str, Any]]":
        """Expose the asynchronous event queue used by interactive modes."""

        return self._event_queue

    def connect(self) -> str:
        """Establish the websocket session and return the authenticated identity."""

        self._thread = threading.Thread(target=self._thread_main, daemon=True)
        self._thread.start()

        if not self._hello_event.wait(timeout=self.STARTUP_TIMEOUT_SECONDS):
            raise RuntimeError(
                "Server did not complete the authentication handshake "
                f"within {self.STARTUP_TIMEOUT_SECONDS} seconds. "
                "Check the WebSocket URL and whether the Render service is awake."
            )
        if self._startup_error is not None:
            raise RuntimeError(self._startup_error)
        if self._hello_payload is None:
            raise RuntimeError("Connection closed during authentication.")
        return str(self._hello_payload.get("identity", "")).strip()

    def close(self) -> None:
        """Close the background websocket connection cleanly."""

        self._stop_requested = True
        if self._loop is not None and self._websocket is not None:
            future = asyncio.run_coroutine_threadsafe(self._websocket.close(), self._loop)
            with contextlib.suppress(Exception):
                future.result(timeout=5)

    def request(self, message_type: str, **payload: Any) -> dict[str, Any]:
        """Send a request and synchronously wait for its response."""

        request_id = f"req-{next(self._request_counter)}-{uuid.uuid4().hex[:8]}"
        response_queue: "queue.Queue[dict[str, Any]]" = queue.Queue(maxsize=1)
        self._response_waiters[request_id] = response_queue
        try:
            self._send({"type": message_type, "request_id": request_id, **payload})
            response = response_queue.get(timeout=15)
        except queue.Empty as exc:
            raise RuntimeError(f"Timed out waiting for response to {message_type}.") from exc
        finally:
            self._response_waiters.pop(request_id, None)

        if not response.get("ok", False):
            raise RequestError(str(response.get("error") or response.get("message") or "request failed"))
        return response

    def send_realtime_message(self, body: str) -> dict[str, Any]:
        """Send a realtime chat message to the active peer."""

        return self.request("realtime_send", body=body)

    def _thread_main(self) -> None:
        """Run the asyncio event loop in a dedicated thread."""

        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._run())
        finally:
            self._hello_event.set()
            loop.close()

    async def _run(self) -> None:
        """Open the websocket, authenticate, and dispatch server messages."""

        ssl_context = None
        if self._config.server_url.startswith("wss://"):
            ssl_context = ssl.create_default_context()

        try:
            async with connect(
                self._config.server_url,
                ssl=ssl_context,
                open_timeout=self.STARTUP_TIMEOUT_SECONDS,
            ) as websocket:
                self._websocket = websocket
                await self._authenticate()
                async for raw_message in websocket:
                    if not isinstance(raw_message, str):
                        continue
                    payload = decode_message(raw_message)
                    message_type = str(payload.get("type", "")).strip()
                    if message_type == "response":
                        request_id = str(payload.get("request_id", "")).strip()
                        waiter = self._response_waiters.get(request_id)
                        if waiter is not None:
                            waiter.put(payload)
                        continue
                    self._event_queue.put(payload)
        except (asyncio.TimeoutError, ConnectionClosed, OSError, ProtocolError, RequestError) as exc:
            self._startup_error = str(exc) or exc.__class__.__name__
            self._hello_event.set()
            self._event_queue.put({"type": "server_notice", "message": self._startup_error})
        except Exception as exc:
            self._startup_error = f"{exc.__class__.__name__}: {exc}"
            self._hello_event.set()
            self._event_queue.put({"type": "server_notice", "message": str(exc)})
        finally:
            self._hello_event.set()
            self._event_queue.put({"type": "server_notice", "message": "Connection closed."})

    async def _authenticate(self) -> None:
        """Complete the app-layer certificate authentication handshake."""

        if self._websocket is None:
            raise RuntimeError("WebSocket is not available.")
        raw_message = await asyncio.wait_for(self._websocket.recv(), timeout=10)
        if not isinstance(raw_message, str):
            raise ProtocolError("Authentication challenge must be a text frame.")
        challenge = decode_message(raw_message)
        if str(challenge.get("type", "")).strip() != "auth_challenge":
            raise ProtocolError("Expected auth_challenge from server.")

        nonce = str(challenge.get("nonce", "")).strip()
        if not nonce:
            raise ProtocolError("Authentication challenge did not include a nonce.")

        await self._websocket.send(
            encode_message(
                {
                    "type": "auth_response",
                    "certificate_pem": self._config.identity.certificate_pem,
                    "signature": sign_nonce(self._private_key, nonce),
                }
            )
        )

        raw_hello = await asyncio.wait_for(self._websocket.recv(), timeout=10)
        if not isinstance(raw_hello, str):
            raise ProtocolError("Server greeting must be a text frame.")
        hello_payload = decode_message(raw_hello)
        if str(hello_payload.get("type", "")).strip() != "hello":
            raise ProtocolError("Expected hello after authentication.")
        self._hello_payload = hello_payload
        self._hello_event.set()
        self._event_queue.put(hello_payload)

    def _send(self, payload: dict[str, Any]) -> None:
        """Schedule a websocket send on the background event loop."""

        if self._loop is None or self._websocket is None:
            raise RuntimeError("Not connected to server.")
        future = asyncio.run_coroutine_threadsafe(self._websocket.send(encode_message(payload)), self._loop)
        future.result(timeout=10)


class OfflineSendMode:
    """Implements the `/send` loop where each message disappears after sending."""

    def __init__(self, connection: SecureClientConnection) -> None:
        self._connection = connection

    def run(self, recipient: str) -> None:
        """Send offline messages until the user enters `/q`."""

        clear_terminal()
        print(f"Offline send mode -> {recipient}. Type messages. Enter /q to exit.")
        while True:
            try:
                line = input("> ")
            except (EOFError, KeyboardInterrupt):
                print()
                return

            if line.strip() == "/q":
                clear_terminal()
                return
            if not line.strip():
                continue

            self._connection.request("send_offline", to=recipient, body=line.rstrip())
            clear_terminal()


class OfflineReadMode:
    """Implements one-by-one offline message reading with fresh passphrase gating."""

    def __init__(self, connection: SecureClientConnection, config: ClientConfig) -> None:
        self._connection = connection
        self._config = config

    def run(self) -> None:
        """Authenticate locally, then read messages one at a time until the user quits."""

        passphrase = getpass.getpass("Enter passphrase for /read: ")
        try:
            load_private_key(self._config.key_path, passphrase)
        except (ValueError, TypeError):
            print("Authentication failed.")
            return

        response = self._connection.request("read_next")
        if not response.get("pending", False):
            clear_terminal()
            print("No messages pending")
            return

        current_message = response["message_data"]
        while True:
            self._render_message(current_message)
            key = self._read_single_key()
            if key == "q":
                clear_terminal()
                return
            if key != "n":
                continue

            response = self._connection.request("read_next")
            if not response.get("pending", False):
                clear_terminal()
                print("No messages pending")
                return
            current_message = response["message_data"]

    def _render_message(self, message: dict[str, Any]) -> None:
        """Display exactly one pending message at a time."""

        clear_terminal()
        print(f"From: {message['from']}")
        print(f"Sent: {message['sent_at']}")
        print()
        print(message["body"])
        print()
        print("Press 'n' for next message or 'q' to exit.")

    @staticmethod
    def _read_single_key() -> str:
        """Read one key from stdin without Enter (cross-platform)."""
        import sys

        if sys.platform.startswith('win'):
            import msvcrt
            key = msvcrt.getch()
            if key in (b'\x00', b'\xe0'):
                key = msvcrt.getch()
            try:
                return key.decode('utf-8')
            except UnicodeDecodeError:
                return ''
        else:
            import termios
            import tty

            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                return sys.stdin.read(1)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


class RealtimeChatMode:
    """Runs the `/connect` realtime chat UI where only one message is visible."""

    def __init__(self, connection: SecureClientConnection) -> None:
        self._connection = connection

    def run(self, peer: str) -> None:
        """Enter realtime mode until the user presses Ctrl+C."""

        response = self._connection.request("connect_mode_enter", peer=peer)
        initial_status = str(response.get("message", "connected to server"))
        try:
            curses.wrapper(self._curses_main, initial_status)
        finally:
            try:
                self._connection.request("connect_mode_leave")
            except Exception:
                pass

    def _curses_main(self, stdscr: Any, initial_status: str) -> None:
        """Render the realtime chat interface with one live message area."""

        curses.curs_set(1)
        curses.use_default_colors()
        stdscr.timeout(50)

        state = {
            "status": initial_status,
            "latest_message": "",
            "input_line": "",
        }

        def redraw() -> None:
            stdscr.erase()
            height, width = stdscr.getmaxyx()
            prompt_row = height - 1
            stdscr.addstr(0, 0, state["status"][: width - 1], curses.A_BOLD)
            if state["latest_message"]:
                stdscr.addstr(2, 0, state["latest_message"][: width - 1])
            prompt = "You: " + state["input_line"]
            stdscr.addstr(prompt_row, 0, prompt[: width - 1])
            stdscr.move(prompt_row, min(len(prompt), width - 1))
            stdscr.refresh()

        while True:
            self._drain_events(state)

            redraw()
            key = stdscr.getch()
            if key == curses.ERR:
                continue
            if key == CLEAR_MESSAGE_KEY:
                state["latest_message"] = ""
                continue
            if key == 3:
                raise KeyboardInterrupt
            if key in (curses.KEY_ENTER, 10, 13):
                body = state["input_line"].strip()
                state["input_line"] = ""
                if not body:
                    continue
                try:
                    response = self._connection.send_realtime_message(body)
                    state["status"] = str(response.get("message", state["status"]))
                except RequestError as exc:
                    state["status"] = str(exc)
                continue
            if key in (curses.KEY_BACKSPACE, 127, 8):
                state["input_line"] = state["input_line"][:-1]
                continue
            if 32 <= key <= 126:
                state["input_line"] += chr(key)

    def _drain_events(self, state: dict[str, str]) -> None:
        """Consume queued events for the realtime UI."""

        while True:
            try:
                payload = self._connection.event_queue.get_nowait()
            except queue.Empty:
                return
            message_type = str(payload.get("type", "")).strip()
            if message_type == "realtime_status":
                state["status"] = str(payload.get("message", ""))
                continue
            if message_type == "realtime_message":
                sender = str(payload.get("from", "peer"))
                body = str(payload.get("body", ""))
                state["latest_message"] = f"{sender}: {body}"
                continue
            if message_type == "server_notice":
                state["status"] = str(payload.get("message", ""))


class CommandShell:
    """Interactive command shell driving all user-visible client modes."""

    def __init__(self, config: ClientConfig, connection: SecureClientConnection, identity: str) -> None:
        self._config = config
        self._connection = connection
        self._identity = identity
        self._peer_identity = other_user(identity)
        self._send_mode = OfflineSendMode(connection)
        self._read_mode = OfflineReadMode(connection, config)
        self._realtime_mode = RealtimeChatMode(connection)

    def run(self) -> int:
        """Run the command shell until the user exits."""

        print(f"Authenticated as {self._identity}")
        print("Type /help for commands.")
        while True:
            try:
                raw_command = input("chat> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return 0

            if not raw_command:
                continue
            if raw_command == "/exit":
                return 0
            if raw_command == "/help":
                self._print_help()
                continue
            if raw_command == "/send":
                self._send_mode.run(self._peer_identity)
                continue
            if raw_command == "/read":
                self._read_mode.run()
                continue
            if raw_command == "/status":
                self._show_status()
                continue
            if raw_command == "/connect":
                try:
                    self._realtime_mode.run(self._peer_identity)
                except KeyboardInterrupt:
                    clear_terminal()
                continue

            print("Unknown command. Type /help for commands.")

    @staticmethod
    def _print_help() -> None:
        """Show supported shell commands."""

        print("/connect         Start realtime chat mode with the other user")
        print("/send            Start offline send mode to the other user")
        print("/read            Read offline messages one by one")
        print("/status          Show pending count and latest 3 read messages")
        print("/help            Show this help")
        print("/exit            Quit")

    def _show_status(self) -> None:
        """Render sender-side receipt information from the server."""

        response = self._connection.request("status")
        print(f"Pending messages: {response['pending_count']}")
        print(f"Read messages: {response['read_count']}")
        if response["read_messages"]:
            for item in response["read_messages"]:
                print(
                    f"Read by {item['recipient']} at {item['read_at']} "
                    f"(sent {item['sent_at']})"
                )


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for the Render-compatible chat client."""

    parser = argparse.ArgumentParser(description="Render-compatible secure chat client")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Server host")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Server port")
    parser.add_argument(
        "--server-url",
        default="",
        help="Explicit websocket URL, for example wss://your-app.onrender.com/ws",
    )
    parser.add_argument(
        "--ws-path",
        default=DEFAULT_WS_PATH,
        help="WebSocket path when building a URL from host and port",
    )
    parser.add_argument(
        "--secure",
        action="store_true",
        help="Use wss:// when building a URL from host and port",
    )
    parser.add_argument(
        "--cert",
        required=True,
        help="Client certificate path",
    )
    parser.add_argument(
        "--key",
        required=True,
        help="Client private key path",
    )
    return parser.parse_args()


def build_config(args: argparse.Namespace) -> ClientConfig:
    """Create immutable client configuration from parsed arguments."""

    identity = CertificateIdentity.from_certificate(args.cert, args.key)
    server_url = args.server_url or build_ws_url(
        host=args.host,
        port=args.port,
        secure=args.secure,
        path=args.ws_path,
    )
    return ClientConfig(
        server_url=server_url,
        cert_path=Path(args.cert).expanduser().resolve(),
        key_path=Path(args.key).expanduser().resolve(),
        identity=identity,
    )


def main() -> int:
    """Program entry point."""

    args = parse_args()
    config = build_config(args)

    passphrase = getpass.getpass("Enter certificate passphrase: ")
    try:
        private_key = load_private_key(config.key_path, passphrase)
    except (ValueError, TypeError):
        print("Failed to unlock client certificate.")
        return 1

    connection = SecureClientConnection(config, private_key)
    try:
        identity = connection.connect()
    except Exception as exc:
        print(f"Could not connect to server: {exc}")
        return 1

    try:
        shell = CommandShell(config, connection, identity)
        return shell.run()
    finally:
        connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
