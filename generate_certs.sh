#!/usr/bin/env bash

set -euo pipefail

# Generate a private CA and two encrypted client certificates whose common
# names map directly to chat identities. The Render deployment uses its own
# edge TLS certificate, so this app doesn't need a server certificate.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${SCRIPT_DIR}/certificates"

CA_SUBJECT="${CA_SUBJECT:-/CN=Secure Chat CA}"
CLIENT_A_SUBJECT="${CLIENT_A_SUBJECT:-/CN=A}"
CLIENT_B_SUBJECT="${CLIENT_B_SUBJECT:-/CN=B}"

CLIENT_A_PASSPHRASE="${CLIENT_A_PASSPHRASE:-changeit-a}"
CLIENT_B_PASSPHRASE="${CLIENT_B_PASSPHRASE:-changeit-b}"

mkdir -p "${CERT_DIR}"
cd "${CERT_DIR}"

rm -f ca.crt ca.key ca.srl a.crt a.csr a.key b.crt b.csr b.key

openssl genrsa -out ca.key 4096
openssl req -x509 -new -key ca.key -sha256 -days 3650 -out ca.crt -subj "${CA_SUBJECT}"

openssl genrsa -aes256 -passout "pass:${CLIENT_A_PASSPHRASE}" -out a.key 2048
openssl req -new -key a.key -passin "pass:${CLIENT_A_PASSPHRASE}" -out a.csr -subj "${CLIENT_A_SUBJECT}"
openssl x509 -req -in a.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out a.crt -days 825 -sha256

openssl genrsa -aes256 -passout "pass:${CLIENT_B_PASSPHRASE}" -out b.key 2048
openssl req -new -key b.key -passin "pass:${CLIENT_B_PASSPHRASE}" -out b.csr -subj "${CLIENT_B_SUBJECT}"
openssl x509 -req -in b.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out b.crt -days 825 -sha256

echo "Certificates written to ${CERT_DIR}"
echo "Client A passphrase: ${CLIENT_A_PASSPHRASE}"
echo "Client B passphrase: ${CLIENT_B_PASSPHRASE}"
