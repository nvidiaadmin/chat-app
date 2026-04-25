# Two-User Local Messaging App

This app includes:
- A local REST server storing messages in SQLite
- A Python CLI client for terminal usage

## Features

- Only users `A` and `B` are allowed
- `send` stores one message at a time with IST timestamp
- `read` returns unread messages for the current user in arrival order
- Messages returned by `read` are deleted immediately from the database

## Run server

```bash
python3 server.py --host 127.0.0.1 --port 8000
```

Optional:
- `--db /path/to/messages.sqlite3` to choose DB location
- Environment variables are also supported:
  - `HOST` (default `0.0.0.0`)
  - `PORT` (default `8000`)
  - `DB_PATH` (SQLite file path)

## Deploy on Render

This folder includes `render.yaml` for one-click blueprint deploy.

- Start command: `python server.py`
- Health endpoint: `GET /health`
- Render injects `PORT`; server reads it automatically.

Important for SQLite on Render:
- `DB_PATH` is set to `/tmp/messages.sqlite3` in `render.yaml` (ephemeral storage).
- For persistent messages, attach a Render disk and set `DB_PATH` to something like `/var/data/messages.sqlite3`.

## Read Passphrase Authentication

`/messages/read` requires a shared passphrase.

1) Choose a short passphrase (example: `lotus47`)
2) Generate SHA-256 hash:

```bash
python3 - <<'PY'
import hashlib
print(hashlib.sha256("lotus47".encode("utf-8")).hexdigest())
PY
```

3) Set server environment variable:
- `READ_KEY_SHA256=<the hash value>`

Client behavior:
- `chat.py` and `cli.py` prompt for passphrase on every read
- Client sends only SHA-256 hash (`read_key_hash`) for authentication

## CLI usage

From another terminal:

```bash
python3 cli.py --user A send "Hello from A"
python3 cli.py --user B read
```

More examples:

```bash
python3 cli.py --user B send "Reply from B"
python3 cli.py --user A read
python3 cli.py --user A read
```

If no unread messages are present, `read` prints `No unread messages.`
