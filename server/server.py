#!/usr/bin/env python3
import argparse
import hmac
import json
import os
import hashlib
import sqlite3
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

ALLOWED_USERS = {"A", "B"}
IST = ZoneInfo("Asia/Kolkata")


class MessageStore:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender TEXT NOT NULL,
                    receiver TEXT NOT NULL,
                    body TEXT NOT NULL,
                    sent_at TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def add_message(self, sender: str, receiver: str, body: str) -> dict[str, Any]:
        sent_at = datetime.now(IST).isoformat()
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO messages (sender, receiver, body, sent_at)
                VALUES (?, ?, ?, ?)
                """,
                (sender, receiver, body, sent_at),
            )
            conn.commit()
            return {"id": cursor.lastrowid, "sent_at": sent_at}

    def read_and_delete_messages(self, receiver: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, sender, receiver, body, sent_at
                FROM messages
                WHERE receiver = ?
                ORDER BY id ASC
                """,
                (receiver,),
            ).fetchall()

            if rows:
                ids = [row["id"] for row in rows]
                placeholders = ",".join("?" for _ in ids)
                conn.execute(f"DELETE FROM messages WHERE id IN ({placeholders})", ids)
                conn.commit()

            return [
                {
                    "id": row["id"],
                    "from": row["sender"],
                    "to": row["receiver"],
                    "message": row["body"],
                    "sent_at": row["sent_at"],
                }
                for row in rows
            ]


class MessageHandler(BaseHTTPRequestHandler):
    store: MessageStore

    def _expected_read_key_hash(self) -> str:
        return str(os.getenv("READ_KEY_SHA256", "")).strip().lower()

    def _send_json(self, status_code: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _parse_json_body(self) -> dict[str, Any] | None:
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length <= 0:
            return None

        raw_body = self.rfile.read(content_length)
        try:
            return json.loads(raw_body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/messages":
            self._handle_send_message()
            return
        if self.path == "/messages/read":
            self._handle_read_messages()
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found"})

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/", "/health"):
            self._send_json(HTTPStatus.OK, {"status": "ok"})
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found"})

    def _handle_send_message(self) -> None:
        payload = self._parse_json_body()
        if payload is None:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid JSON payload"})
            return

        sender = str(payload.get("from_user", "")).strip()
        receiver = str(payload.get("to_user", "")).strip()
        message = str(payload.get("message", "")).strip()

        if sender not in ALLOWED_USERS or receiver not in ALLOWED_USERS:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "from_user and to_user must be either A or B"},
            )
            return
        if sender == receiver:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "from_user and to_user must be different"},
            )
            return
        if not message:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "message cannot be empty"})
            return

        saved = self.store.add_message(sender=sender, receiver=receiver, body=message)
        self._send_json(
            HTTPStatus.CREATED,
            {"status": "stored", "message_id": saved["id"], "sent_at": saved["sent_at"]},
        )

    def _handle_read_messages(self) -> None:
        payload = self._parse_json_body()
        if payload is None:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid JSON payload"})
            return

        user = str(payload.get("user", "")).strip()
        if user not in ALLOWED_USERS:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "user must be A or B"})
            return

        provided_hash = str(payload.get("read_key_hash", "")).strip().lower()
        expected_hash = self._expected_read_key_hash()
        if not expected_hash:
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "Server read key is not configured"},
            )
            return
        # Allow either a pre-hashed value or a raw passphrase from legacy clients.
        if len(provided_hash) != 64:
            provided_hash = hashlib.sha256(provided_hash.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(provided_hash, expected_hash):
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Authentication failed"})
            return

        messages = self.store.read_and_delete_messages(receiver=user)
        self._send_json(
            HTTPStatus.OK,
            {"count": len(messages), "messages": messages, "status": "read_and_deleted"},
        )

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        # Keep server output concise in terminal usage.
        return


def create_server(host: str, port: int, db_path: str) -> ThreadingHTTPServer:
    MessageHandler.store = MessageStore(db_path=db_path)
    return ThreadingHTTPServer((host, port), MessageHandler)


def main() -> None:
    parser = argparse.ArgumentParser(description="Two-user local message REST server")
    parser.add_argument(
        "--host",
        default=os.getenv("HOST", "0.0.0.0"),
        help="Host to bind to (default: HOST env or 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        default=int(os.getenv("PORT", "8000")),
        type=int,
        help="Port to bind to (default: PORT env or 8000)",
    )
    parser.add_argument(
        "--db",
        default=os.getenv(
            "DB_PATH",
            str(Path(__file__).with_name("messages.sqlite3")),
        ),
        help="SQLite database file path (default: DB_PATH env or local file)",
    )
    args = parser.parse_args()

    server = create_server(host=args.host, port=args.port, db_path=args.db)
    print(f"Server listening on http://{args.host}:{args.port} using db {args.db}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
