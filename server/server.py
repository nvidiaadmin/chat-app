#!/usr/bin/env python3
"""Render-compatible aiohttp chat server with certificate-based app auth."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import os
import secrets
import signal
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from aiohttp import WSMsgType, web

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from common import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_WS_PATH,
    ProtocolError,
    decode_message,
    encode_message,
    extract_common_name_from_certificate,
    load_certificate_from_pem,
    verify_certificate_issued_by,
    verify_nonce_signature,
)

IST = ZoneInfo("Asia/Kolkata")


def current_timestamp() -> str:
    """Return the current timestamp in ISO 8601 format."""

    return datetime.now(IST).isoformat(timespec="seconds")


class MessageRepository:
    """Encapsulates all SQLite access for offline messages and read receipts."""

    def __init__(self, database_path: str | Path) -> None:
        self._database_path = str(Path(database_path).expanduser().resolve())
        self._initialise()

    def _connect(self) -> sqlite3.Connection:
        """Open a SQLite connection configured for dictionary-style row access."""

        connection = sqlite3.connect(self._database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialise(self) -> None:
        """Create database tables if they do not already exist."""

        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS pending_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    body TEXT NOT NULL,
                    sent_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS read_receipts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    original_message_id INTEGER NOT NULL,
                    sender TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    body TEXT NOT NULL,
                    sent_at TEXT NOT NULL,
                    read_at TEXT NOT NULL
                )
                """
            )
            connection.commit()

    def enqueue_offline_message(self, sender: str, recipient: str, body: str) -> dict[str, Any]:
        """Persist an offline message for later reading."""

        sent_at = current_timestamp()
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO pending_messages (sender, recipient, body, sent_at)
                VALUES (?, ?, ?, ?)
                """,
                (sender, recipient, body, sent_at),
            )
            connection.commit()
        return {"message_id": cursor.lastrowid, "sent_at": sent_at}

    def pop_next_message_for_reader(self, recipient: str) -> dict[str, Any] | None:
        """Atomically fetch and delete the oldest pending message for a recipient."""

        read_at = current_timestamp()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT id, sender, recipient, body, sent_at
                FROM pending_messages
                WHERE recipient = ?
                ORDER BY id ASC
                LIMIT 1
                """,
                (recipient,),
            ).fetchone()
            if row is None:
                connection.commit()
                return None

            connection.execute("DELETE FROM pending_messages WHERE id = ?", (row["id"],))
            connection.execute(
                """
                INSERT INTO read_receipts (
                    original_message_id,
                    sender,
                    recipient,
                    body,
                    sent_at,
                    read_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    row["id"],
                    row["sender"],
                    row["recipient"],
                    row["body"],
                    row["sent_at"],
                    read_at,
                ),
            )
            connection.commit()

        return {
            "message_id": row["id"],
            "from": row["sender"],
            "to": row["recipient"],
            "body": row["body"],
            "sent_at": row["sent_at"],
            "read_at": read_at,
        }

    def get_status_for_sender(self, sender: str) -> dict[str, Any]:
        """Return aggregate pending/read counts and the latest three receipts."""

        with self._connect() as connection:
            pending_count = connection.execute(
                "SELECT COUNT(*) FROM pending_messages WHERE sender = ?",
                (sender,),
            ).fetchone()[0]
            receipts = connection.execute(
                """
                SELECT recipient, body, sent_at, read_at
                FROM read_receipts
                WHERE sender = ?
                ORDER BY id DESC
                LIMIT 3
                """,
                (sender,),
            ).fetchall()
            read_count = connection.execute(
                "SELECT COUNT(*) FROM read_receipts WHERE sender = ?",
                (sender,),
            ).fetchone()[0]

        return {
            "pending_count": int(pending_count),
            "read_count": int(read_count),
            "read_messages": [
                {
                    "recipient": row["recipient"],
                    "body": row["body"],
                    "sent_at": row["sent_at"],
                    "read_at": row["read_at"],
                }
                for row in receipts
            ],
        }


@dataclass
class RealtimeState:
    """Tracks realtime pairing state for one connected identity."""

    desired_peer: str | None = None
    active_peer: str | None = None


class ClientConnection:
    """Represents one authenticated WebSocket client connection."""

    def __init__(self, websocket: web.WebSocketResponse, identity: str) -> None:
        self.websocket = websocket
        self.identity = identity
        self.realtime = RealtimeState()

    async def send(self, payload: dict[str, Any]) -> None:
        """Send one JSON protocol payload."""

        await self.websocket.send_str(encode_message(payload))

    async def send_response(self, request_id: str | None, ok: bool, **payload: Any) -> None:
        """Send a structured response tied to a request id."""

        message = {"type": "response", "request_id": request_id, "ok": ok}
        message.update(payload)
        await self.send(message)

    async def close(self) -> None:
        """Close the websocket connection."""

        await self.websocket.close()


class CertificateAuthenticator:
    """Validates client certificates and possession proofs at the app layer."""

    def __init__(self, ca_certificate_path: str | Path) -> None:
        self._ca_certificate = load_certificate_from_pem(
            Path(ca_certificate_path).expanduser().resolve().read_text(encoding="utf-8")
        )

    async def authenticate(self, websocket: web.WebSocketResponse) -> ClientConnection:
        """Challenge the client and verify its signed certificate proof."""

        nonce = secrets.token_urlsafe(32)
        await websocket.send_str(encode_message({"type": "auth_challenge", "nonce": nonce}))

        message = await asyncio.wait_for(websocket.receive(), timeout=10)
        if message.type != WSMsgType.TEXT:
            raise ProtocolError("Authentication payload must be a text frame.")

        payload = decode_message(message.data)
        if str(payload.get("type", "")).strip() != "auth_response":
            raise ProtocolError("Expected auth_response during authentication.")

        certificate_pem = str(payload.get("certificate_pem", "")).strip()
        signature = str(payload.get("signature", "")).strip()
        if not certificate_pem or not signature:
            raise ProtocolError("Authentication payload is incomplete.")

        certificate = load_certificate_from_pem(certificate_pem)
        verify_certificate_issued_by(certificate, self._ca_certificate)
        verify_nonce_signature(certificate, nonce, signature)
        identity = extract_common_name_from_certificate(certificate)
        return ClientConnection(websocket=websocket, identity=identity)


class RealtimeCoordinator:
    """Coordinates realtime pairing and message relay between connected users."""

    def __init__(self) -> None:
        self._clients: dict[str, ClientConnection] = {}
        self._lock = asyncio.Lock()

    async def register(self, client: ClientConnection) -> None:
        """Register a client as online, replacing any previous live connection."""

        async with self._lock:
            previous = self._clients.get(client.identity)
            self._clients[client.identity] = client
        if previous and previous is not client:
            await previous.send(
                {
                    "type": "server_notice",
                    "message": "This session was replaced by a newer login.",
                }
            )
            await previous.close()

    async def unregister(self, client: ClientConnection) -> None:
        """Remove a disconnected client and unwind any active realtime pair."""

        async with self._lock:
            current = self._clients.get(client.identity)
            if current is client:
                self._clients.pop(client.identity, None)
            active_peer = client.realtime.active_peer
            desired_peer = client.realtime.desired_peer
            client.realtime.active_peer = None
            client.realtime.desired_peer = None

            peer = self._clients.get(active_peer) if active_peer else None
            waiting_peer = self._clients.get(desired_peer) if desired_peer else None

            if peer and peer.realtime.active_peer == client.identity:
                peer.realtime.active_peer = None
                if peer.realtime.desired_peer == client.identity:
                    peer.realtime.desired_peer = None
            if waiting_peer and waiting_peer.realtime.desired_peer == client.identity:
                waiting_peer.realtime.desired_peer = None

        if peer:
            await peer.send(
                {
                    "type": "realtime_status",
                    "message": f"{client.identity} disconnected.",
                    "connected": False,
                }
            )

    async def enter(self, client: ClientConnection, peer_identity: str) -> dict[str, Any]:
        """Place a client into realtime mode and pair it when both sides agree."""

        async with self._lock:
            client.realtime.desired_peer = peer_identity
            client.realtime.active_peer = None
            peer = self._clients.get(peer_identity)
            paired = False
            if peer and peer.realtime.desired_peer == client.identity:
                client.realtime.active_peer = peer_identity
                peer.realtime.active_peer = client.identity
                paired = True

        if paired and peer:
            await client.send(
                {"type": "realtime_status", "message": "device connected.", "connected": True}
            )
            await peer.send(
                {"type": "realtime_status", "message": "device connected.", "connected": True}
            )
            return {"paired": True}
        return {"paired": False}

    async def leave(self, client: ClientConnection) -> None:
        """Remove a client from realtime mode and notify the peer if required."""

        async with self._lock:
            active_peer = client.realtime.active_peer
            desired_peer = client.realtime.desired_peer
            client.realtime.active_peer = None
            client.realtime.desired_peer = None
            peer = self._clients.get(active_peer) if active_peer else None
            waiting_peer = self._clients.get(desired_peer) if desired_peer else None
            if peer and peer.realtime.active_peer == client.identity:
                peer.realtime.active_peer = None
            if peer and peer.realtime.desired_peer == client.identity:
                peer.realtime.desired_peer = None
            if waiting_peer and waiting_peer.realtime.desired_peer == client.identity:
                waiting_peer.realtime.desired_peer = None

        if peer:
            await peer.send(
                {
                    "type": "realtime_status",
                    "message": f"{client.identity} left realtime mode.",
                    "connected": False,
                }
            )

    async def relay_message(self, sender: ClientConnection, body: str) -> bool:
        """Relay a realtime message to the active peer if one exists."""

        async with self._lock:
            peer_identity = sender.realtime.active_peer
            peer = self._clients.get(peer_identity) if peer_identity else None
            peer_is_active = bool(peer and peer.realtime.active_peer == sender.identity)

        if not peer_is_active or peer is None:
            return False

        await peer.send(
            {
                "type": "realtime_message",
                "from": sender.identity,
                "body": body,
                "sent_at": current_timestamp(),
            }
        )
        return True


class SecureChatServer:
    """Owns the aiohttp application, request handling, and persistence layers."""

    def __init__(self, host: str, port: int, path: str, database_path: str | Path, ca_cert: str | Path) -> None:
        self._host = host
        self._port = port
        self._path = path if path.startswith("/") else f"/{path}"
        self._repository = MessageRepository(database_path)
        self._authenticator = CertificateAuthenticator(ca_cert)
        self._realtime = RealtimeCoordinator()

    async def run(self) -> None:
        """Start serving HTTP and websocket clients until the process receives SIGTERM."""

        app = web.Application()
        app.add_routes(
            [
                web.get("/health", self._health_handler),
                web.get("/healthz", self._health_handler),
                web.get(self._path, self._websocket_handler),
            ]
        )

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, self._host, self._port)
        await site.start()
        print(f"Secure chat server listening on {self._host}:{self._port}{self._path}")

        stop_event = asyncio.Event()
        loop = asyncio.get_running_loop()
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(signal.SIGTERM, stop_event.set)
            loop.add_signal_handler(signal.SIGINT, stop_event.set)

        await stop_event.wait()
        await runner.cleanup()

    async def _health_handler(self, request: web.Request) -> web.Response:
        """Return a simple health check response for GET and HEAD probes."""

        return web.Response(text="OK\n")

    async def _websocket_handler(self, request: web.Request) -> web.WebSocketResponse:
        """Upgrade the request to a websocket and process the chat protocol."""

        websocket = web.WebSocketResponse(heartbeat=30)
        await websocket.prepare(request)

        client: ClientConnection | None = None
        try:
            client = await self._authenticator.authenticate(websocket)
            await self._realtime.register(client)
            await client.send(
                {"type": "hello", "identity": client.identity, "message": "connected to server"}
            )

            async for message in websocket:
                if message.type == WSMsgType.TEXT:
                    payload = decode_message(message.data)
                    await self._handle_request(client, payload)
                    continue
                if message.type in (WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.CLOSING):
                    break
                if message.type == WSMsgType.ERROR:
                    break
        except (ProtocolError, ValueError, asyncio.TimeoutError) as exc:
            print(f"WebSocket authentication/protocol error: {exc}", flush=True)
            if client is not None:
                await client.send({"type": "server_notice", "message": str(exc)})
            else:
                with contextlib.suppress(Exception):
                    await websocket.send_str(encode_message({"type": "server_notice", "message": str(exc)}))
        finally:
            if client is not None:
                await self._realtime.leave(client)
                await self._realtime.unregister(client)
                await client.close()

        return websocket

    async def _handle_request(self, client: ClientConnection, payload: dict[str, Any]) -> None:
        """Dispatch a request payload to the appropriate handler."""

        message_type = str(payload.get("type", "")).strip()
        request_id = str(payload.get("request_id", "")).strip() or None

        if message_type == "send_offline":
            recipient = str(payload.get("to", "")).strip()
            body = str(payload.get("body", "")).strip()
            await self._handle_send_offline(client, request_id, recipient, body)
            return
        if message_type == "read_next":
            await self._handle_read_next(client, request_id)
            return
        if message_type == "status":
            await self._handle_status(client, request_id)
            return
        if message_type == "connect_mode_enter":
            peer = str(payload.get("peer", "")).strip()
            await self._handle_connect_enter(client, request_id, peer)
            return
        if message_type == "connect_mode_leave":
            await self._realtime.leave(client)
            await client.send_response(request_id, True, message="left realtime mode")
            return
        if message_type == "realtime_send":
            body = str(payload.get("body", "")).strip()
            if not body:
                await client.send_response(request_id, False, error="message cannot be empty")
                return
            delivered = await self._realtime.relay_message(client, body)
            await client.send_response(
                request_id,
                delivered,
                message="sent" if delivered else "peer not connected",
                sent_at=current_timestamp(),
            )
            return

        await client.send_response(request_id, False, error=f"unknown request type: {message_type}")

    async def _handle_send_offline(
        self,
        client: ClientConnection,
        request_id: str | None,
        recipient: str,
        body: str,
    ) -> None:
        """Validate and store an offline message."""

        if not recipient:
            await client.send_response(request_id, False, error="recipient is required")
            return
        if recipient == client.identity:
            await client.send_response(request_id, False, error="cannot send a message to yourself")
            return
        if not body:
            await client.send_response(request_id, False, error="message cannot be empty")
            return

        saved = self._repository.enqueue_offline_message(client.identity, recipient, body)
        await client.send_response(request_id, True, **saved)

    async def _handle_read_next(self, client: ClientConnection, request_id: str | None) -> None:
        """Return the next pending offline message, deleting it from the inbox."""

        message = self._repository.pop_next_message_for_reader(client.identity)
        if message is None:
            await client.send_response(request_id, True, pending=False, message="No messages pending")
            return
        await client.send_response(request_id, True, pending=True, message_data=message)

    async def _handle_status(self, client: ClientConnection, request_id: str | None) -> None:
        """Return sender-side delivery status derived from inbox and receipt tables."""

        status = self._repository.get_status_for_sender(client.identity)
        await client.send_response(request_id, True, **status)

    async def _handle_connect_enter(
        self,
        client: ClientConnection,
        request_id: str | None,
        peer: str,
    ) -> None:
        """Place a client into realtime mode and optionally pair it immediately."""

        if not peer:
            await client.send_response(request_id, False, error="peer is required")
            return
        if peer == client.identity:
            await client.send_response(request_id, False, error="cannot connect to yourself")
            return

        result = await self._realtime.enter(client, peer)
        await client.send_response(
            request_id,
            True,
            paired=result["paired"],
            message="connected to server",
        )


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments for the Render-compatible chat server."""

    project_dir = PROJECT_ROOT
    default_certs = project_dir / "certificates"
    parser = argparse.ArgumentParser(description="Render-compatible secure chat server")
    parser.add_argument("--host", default=os.getenv("HOST", DEFAULT_HOST), help="Host/interface to bind")
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("PORT", str(DEFAULT_PORT))),
        help="Port to bind",
    )
    parser.add_argument(
        "--path",
        default=os.getenv("WS_PATH", DEFAULT_WS_PATH),
        help="WebSocket path to accept",
    )
    parser.add_argument(
        "--db",
        default=os.getenv("DB_PATH", str(project_dir / "messages.sqlite3")),
        help="SQLite database path",
    )
    parser.add_argument(
        "--ca-cert",
        default=os.getenv("CA_CERT_PATH", str(default_certs / "ca.crt")),
        help="CA certificate used to verify client certificates",
    )
    return parser.parse_args()


def main() -> None:
    """Program entry point."""

    args = parse_args()
    server = SecureChatServer(
        host=args.host,
        port=args.port,
        path=args.path,
        database_path=args.db,
        ca_cert=args.ca_cert,
    )
    try:
        asyncio.run(server.run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
