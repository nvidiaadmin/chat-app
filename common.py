"""Shared protocol and certificate helpers for the secure chat application."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding

ENCODING = "utf-8"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 10000
DEFAULT_WS_PATH = "/ws"


class ProtocolError(RuntimeError):
    """Raised when a peer sends a malformed protocol message."""


def encode_message(payload: dict[str, Any]) -> str:
    """Serialize a protocol payload as compact JSON text."""

    return json.dumps(payload, separators=(",", ":"))


def decode_message(raw_message: str) -> dict[str, Any]:
    """Decode one JSON protocol message."""

    try:
        payload = json.loads(raw_message)
    except json.JSONDecodeError as exc:
        raise ProtocolError("Received malformed JSON message.") from exc
    if not isinstance(payload, dict):
        raise ProtocolError("Protocol message must decode to an object.")
    return payload


@dataclass(frozen=True)
class CertificateIdentity:
    """Represents the identity extracted from a client certificate."""

    common_name: str
    certificate_path: Path
    key_path: Path
    certificate_pem: str

    @classmethod
    def from_certificate(cls, certificate_path: str | Path, key_path: str | Path) -> "CertificateIdentity":
        """Extract the certificate common name from a PEM certificate file."""

        cert_path = Path(certificate_path).expanduser().resolve()
        certificate_pem = cert_path.read_text(encoding=ENCODING)
        certificate = load_certificate_from_pem(certificate_pem)
        return cls(
            common_name=extract_common_name_from_certificate(certificate),
            certificate_path=cert_path,
            key_path=Path(key_path).expanduser().resolve(),
            certificate_pem=certificate_pem,
        )


def load_certificate_from_pem(certificate_pem: str) -> x509.Certificate:
    """Load a PEM-encoded certificate."""

    return x509.load_pem_x509_certificate(certificate_pem.encode(ENCODING))


def load_private_key(key_path: str | Path, passphrase: str):
    """Load an encrypted PEM private key using the provided passphrase."""

    return serialization.load_pem_private_key(
        Path(key_path).expanduser().resolve().read_bytes(),
        password=passphrase.encode(ENCODING),
    )


def extract_common_name_from_certificate(certificate: x509.Certificate) -> str:
    """Extract the common name from a parsed certificate."""

    attributes = certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if not attributes:
        raise ValueError("Certificate does not contain a common name.")
    common_name = str(attributes[0].value).strip()
    if not common_name:
        raise ValueError("Certificate common name is empty.")
    return common_name


def serialize_certificate_to_pem(certificate: x509.Certificate) -> str:
    """Serialize a parsed certificate back to PEM text."""

    return certificate.public_bytes(Encoding.PEM).decode(ENCODING)


def verify_certificate_issued_by(certificate: x509.Certificate, ca_certificate: x509.Certificate) -> None:
    """Verify that the certificate was issued by the trusted CA and is currently valid."""

    if certificate.issuer != ca_certificate.subject:
        raise ValueError("Certificate issuer does not match the configured CA.")

    now = datetime.now(timezone.utc)
    not_before = getattr(certificate, "not_valid_before_utc", certificate.not_valid_before.replace(tzinfo=timezone.utc))
    not_after = getattr(certificate, "not_valid_after_utc", certificate.not_valid_after.replace(tzinfo=timezone.utc))
    if now < not_before or now > not_after:
        raise ValueError("Certificate is not currently valid.")

    ca_public_key = ca_certificate.public_key()
    _verify_signature(
        public_key=ca_public_key,
        signature=certificate.signature,
        data=certificate.tbs_certificate_bytes,
        hash_algorithm=certificate.signature_hash_algorithm,
    )


def sign_nonce(private_key: Any, nonce: str) -> str:
    """Sign a server-issued nonce and return the signature as base64 text."""

    data = nonce.encode(ENCODING)
    if isinstance(private_key, rsa.RSAPrivateKey):
        signature = private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    elif isinstance(private_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        signature = private_key.sign(data)
    else:
        raise TypeError("Unsupported private key type.")
    return base64.b64encode(signature).decode(ENCODING)


def verify_nonce_signature(certificate: x509.Certificate, nonce: str, signature_b64: str) -> None:
    """Verify the client's signed nonce using the public key in its certificate."""

    signature = base64.b64decode(signature_b64.encode(ENCODING))
    _verify_signature(
        public_key=certificate.public_key(),
        signature=signature,
        data=nonce.encode(ENCODING),
        hash_algorithm=hashes.SHA256(),
    )


def build_ws_url(host: str, port: int, secure: bool, path: str = DEFAULT_WS_PATH) -> str:
    """Build a websocket URL from discrete connection settings."""

    scheme = "wss" if secure else "ws"
    normalized_path = path if path.startswith("/") else f"/{path}"
    return f"{scheme}://{host}:{port}{normalized_path}"


def _verify_signature(public_key: Any, signature: bytes, data: bytes, hash_algorithm: Any) -> None:
    """Verify a signature with support for RSA, EC, and EdDSA keys."""

    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(signature, data, padding.PKCS1v15(), hash_algorithm)
        return
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, data, ec.ECDSA(hash_algorithm))
        return
    if isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        public_key.verify(signature, data)
        return
    raise TypeError("Unsupported public key type.")
