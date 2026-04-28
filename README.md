# Secure Chat Application

This application is a Render-compatible rewrite of the earlier prototype.

It provides:

- WebSocket transport for Render deployment
- App-layer certificate authentication using challenge-response
- Client identity derived from the certificate common name
- `/connect` realtime chat mode relayed through the server
- `/send` offline message send mode backed by SQLite
- `/read` one-by-one offline message reading with a fresh passphrase prompt
- `/status` sender-side read/pending visibility

## Architecture

- Render terminates public HTTPS/WSS at its edge.
- The chat server runs an HTTP health endpoint at `/healthz`.
- Realtime and command traffic run over WebSockets at `/ws`.
- The client proves certificate ownership by signing a server-issued nonce with the private key unlocked from the passphrase.
- The server verifies the client certificate against `certificates/ca.crt`.

## File layout

- `client/client.py`: interactive terminal client
- `server/server.py`: Render-compatible WebSocket server with SQLite storage
- `common.py`: shared protocol and certificate helpers
- `requirements.txt`: Python dependencies for deployment
- `render.yaml`: Render Blueprint
- `generate_certs.sh`: reproducible client-certificate generation script
- `certificates/`: local CA and client certificates

## Generate certificates

The application uses only certificates under `secure_chat_app/certificates`.

Run:

```bash
cd /Users/skinger/ZedProjects/secure_chat_app
./generate_certs.sh
```

The script runs these OpenSSL commands:

```bash
openssl genrsa -out certificates/ca.key 4096
openssl req -x509 -new -key certificates/ca.key -sha256 -days 3650 -out certificates/ca.crt -subj "/CN=Secure Chat CA"

openssl genrsa -aes256 -passout pass:changeit-a -out certificates/a.key 2048
openssl req -new -key certificates/a.key -passin pass:changeit-a -out certificates/a.csr -subj "/CN=A"
openssl x509 -req -in certificates/a.csr -CA certificates/ca.crt -CAkey certificates/ca.key -CAcreateserial -out certificates/a.crt -days 825 -sha256

openssl genrsa -aes256 -passout pass:changeit-b -out certificates/b.key 2048
openssl req -new -key certificates/b.key -passin pass:changeit-b -out certificates/b.csr -subj "/CN=B"
openssl x509 -req -in certificates/b.csr -CA certificates/ca.crt -CAkey certificates/ca.key -CAcreateserial -out certificates/b.crt -days 825 -sha256
```

Default demo passphrases:

- Client A: `changeit-a`
- Client B: `changeit-b`

You can regenerate with different passphrases by exporting `CLIENT_A_PASSPHRASE` and `CLIENT_B_PASSPHRASE` before running the script.

## Local server run

```bash
cd /Users/skinger/ZedProjects/secure_chat_app
python3 -m pip install -r requirements.txt
python3 server/server.py --host 127.0.0.1 --port 10000
```

## Local client run

Terminal 1:

```bash
cd /Users/skinger/ZedProjects/secure_chat_app
python3 client/client.py \
  --host 127.0.0.1 \
  --port 10000 \
  --cert certificates/a.crt \
  --key certificates/a.key
```

Terminal 2:

```bash
cd /Users/skinger/ZedProjects/secure_chat_app
python3 client/client.py \
  --host 127.0.0.1 \
  --port 10000 \
  --cert certificates/b.crt \
  --key certificates/b.key
```

## Render deployment

The checked-in [render.yaml](/Users/skinger/ZedProjects/secure_chat_app/render.yaml) is intended for this server.

It defines:

- a Python web service
- dependency install via `requirements.txt`
- startup with `python server/server.py --host 0.0.0.0`
- a health check path at `/healthz`
- `DB_PATH=/tmp/messages.sqlite3`
- `CA_CERT_PATH=./certificates/ca.crt`
- `WS_PATH=/ws`

Files required in the deployed repo:

- `render.yaml`
- `requirements.txt`
- `server/server.py`
- `common.py`
- `certificates/ca.crt`

Do not deploy private client keys to Render:

- `certificates/a.key`
- `certificates/b.key`
- `certificates/ca.key`

## Render client connection

After deployment, connect the clients to the public Render URL with `wss://`.

Example:

```bash
python3 client/client.py \
  --server-url wss://your-render-service.onrender.com/ws \
  --cert certificates/a.crt \
  --key certificates/a.key
```

## Commands

- `/connect`: enter realtime mode with the other user
- `/send`: enter offline send mode to the other user and keep sending until `/q`
- `/read`: read pending offline messages one by one using `n` and `q`
- `/status`: show pending count and details of the latest 3 read messages
- `/exit`: close the client
