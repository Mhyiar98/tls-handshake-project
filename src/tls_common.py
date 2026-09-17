"""
tls_common.py
=================
Shared building blocks for a *simplified* TLS-style handshake.

This module deliberately mirrors the way a real TLS 1.2/1.3 handshake is
structured so the code can be read as a "walkthrough":

    ClientHello  ->  (client_random, supported cipher suites)
    ServerHello  <-  (server_random, chosen suite, DH public key [+ signature])
    KeyExchange  ->  (client DH public key)
    Derive       ==  shared_secret -> HKDF -> session keys
    Finished     <-> HMAC over the handshake transcript
    AppData      <-> AES-256-GCM records

Nothing here is meant to *replace* a real TLS stack. It is an educational
implementation for an Information Security semester project. Where we take a
shortcut compared to production TLS, the comment says so explicitly.

Author : Mhyiar Elmistere
Course : Information Security - Semester Project (Summer 2026)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import struct
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

PROTOCOL_VERSION = "TLS-STYLE/1.0"          # our own version label
CIPHER_SUITE = "DHE-HKDF-SHA256-AES256GCM"  # the single suite we support
RANDOM_LEN = 32                              # 32-byte client/server random
GCM_NONCE_LEN = 12                           # 96-bit nonce, TLS-record style


# ---------------------------------------------------------------------------
# 1) Diffie-Hellman key exchange
# ---------------------------------------------------------------------------
# We use the standard 2048-bit MODP group defined in RFC 3526 (Group 14).
# Finite-field DH (instead of the elliptic-curve X25519 that TLS 1.3 uses)
# is chosen ON PURPOSE: the modular exponentiation  g^a mod p  is visible in
# plain Python, so the "key exchange" step of the walkthrough is easy to read.
# A note in the report explains that production TLS 1.3 prefers ECDHE/X25519.

# RFC 3526 - 2048-bit MODP Group (id 14)
DH_PRIME_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
DH_PRIME = int(DH_PRIME_HEX, 16)
DH_GENERATOR = 2


@dataclass
class DHKeyPair:
    """An ephemeral Diffie-Hellman key pair (a, g^a mod p)."""

    private: int
    public: int

    @classmethod
    def generate(cls) -> "DHKeyPair":
        # Private exponent: 256 random bits is comfortably strong for this
        # 2048-bit group and keeps the demo fast.
        private = int.from_bytes(os.urandom(32), "big")
        public = pow(DH_GENERATOR, private, DH_PRIME)
        return cls(private=private, public=public)

    def shared_secret(self, peer_public: int) -> bytes:
        """Compute (peer_public)^private mod p and return it as bytes."""
        if not (2 <= peer_public <= DH_PRIME - 2):
            # Reject 0, 1, p-1 etc. which would force a tiny/known secret.
            raise ValueError("Invalid DH public value from peer")
        secret_int = pow(peer_public, self.private, DH_PRIME)
        # Fixed-width big-endian encoding (2048 bits = 256 bytes).
        return secret_int.to_bytes(256, "big")


# ---------------------------------------------------------------------------
# 2) HKDF (RFC 5869) - session-key derivation
# ---------------------------------------------------------------------------
# TLS derives its traffic keys with HKDF. We implement the same
# extract-then-expand construction on top of HMAC-SHA256.


def hkdf_extract(salt: bytes, input_key_material: bytes) -> bytes:
    """HKDF-Extract: PRK = HMAC(salt, IKM)."""
    if not salt:
        salt = b"\x00" * hashlib.sha256().digest_size
    return hmac.new(salt, input_key_material, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand: turn the pseudo-random key into `length` output bytes."""
    output = b""
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(
            prk, previous + info + bytes([counter]), hashlib.sha256
        ).digest()
        output += previous
        counter += 1
    return output[:length]


@dataclass
class SessionKeys:
    """Directional traffic keys derived from the DH shared secret."""

    client_write_key: bytes   # client encrypts with this / server decrypts
    server_write_key: bytes   # server encrypts with this / client decrypts
    master_secret: bytes      # kept for the Finished MAC


def derive_session_keys(
    shared_secret: bytes, client_random: bytes, server_random: bytes
) -> SessionKeys:
    """
    Turn the raw DH shared secret into two AES-256 traffic keys.

    salt = client_random || server_random   (binds keys to THIS handshake)
    """
    salt = client_random + server_random
    prk = hkdf_extract(salt, shared_secret)
    master_secret = hkdf_expand(prk, b"tls-style master secret", 32)
    key_block = hkdf_expand(prk, b"tls-style key expansion", 64)
    return SessionKeys(
        client_write_key=key_block[:32],
        server_write_key=key_block[32:64],
        master_secret=master_secret,
    )


# ---------------------------------------------------------------------------
# 3) Authenticated encryption for application data (AES-256-GCM)
# ---------------------------------------------------------------------------


class RecordCrypter:
    """
    Encrypt/decrypt application records with AES-256-GCM.

    Each direction uses its own key and a per-record incrementing sequence
    number as the nonce, exactly like a TLS record layer. Re-using a
    (key, nonce) pair in GCM is catastrophic, so the counter never repeats.
    """

    def __init__(self, key: bytes):
        self._aesgcm = AESGCM(key)
        self._seq = 0

    def _next_nonce(self) -> bytes:
        nonce = self._seq.to_bytes(GCM_NONCE_LEN, "big")
        self._seq += 1
        return nonce

    def encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        nonce = self._next_nonce()
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce + ciphertext          # ship the nonce alongside

    def decrypt(self, record: bytes, associated_data: bytes = b"") -> bytes:
        nonce, ciphertext = record[:GCM_NONCE_LEN], record[GCM_NONCE_LEN:]
        return self._aesgcm.decrypt(nonce, ciphertext, associated_data)


# ---------------------------------------------------------------------------
# 4) Handshake transcript + Finished MAC
# ---------------------------------------------------------------------------


class Transcript:
    """
    Running SHA-256 hash of every handshake message, in order.

    TLS uses this to make the "Finished" message cover the whole handshake,
    so a man-in-the-middle who tampered with any earlier message is detected.
    """

    def __init__(self) -> None:
        self._hash = hashlib.sha256()

    def add(self, message_bytes: bytes) -> None:
        self._hash.update(message_bytes)

    def digest(self) -> bytes:
        return self._hash.copy().digest()


def finished_mac(master_secret: bytes, transcript_digest: bytes, label: bytes) -> bytes:
    """HMAC over the transcript, keyed by the master secret (TLS Finished)."""
    return hmac.new(master_secret, label + transcript_digest, hashlib.sha256).digest()


# ---------------------------------------------------------------------------
# 5) Long-term server identity (Ed25519) - used only in "secure" mode
# ---------------------------------------------------------------------------
# The hardened variant authenticates the server: it signs its DH public key
# with a long-term Ed25519 key, and the client verifies that signature.
# This is the mitigation for the man-in-the-middle finding.


def load_or_create_server_identity(path: str) -> Ed25519PrivateKey:
    """Load the server's long-term signing key, creating it once if absent."""
    if os.path.exists(path):
        with open(path, "rb") as fh:
            return Ed25519PrivateKey.from_private_bytes(fh.read())
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes_raw()
    with open(path, "wb") as fh:
        fh.write(raw)
    return key


def server_public_key_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes_raw()


def sign_dh_public(
    private_key: Ed25519PrivateKey,
    client_random: bytes,
    server_random: bytes,
    dh_public: int,
) -> bytes:
    """Server signs (client_random || server_random || dh_public)."""
    message = client_random + server_random + dh_public.to_bytes(256, "big")
    return private_key.sign(message)


def verify_dh_signature(
    server_public_raw: bytes,
    client_random: bytes,
    server_random: bytes,
    dh_public: int,
    signature: bytes,
) -> bool:
    """Client verifies the server's signature over its DH public key."""
    message = client_random + server_random + dh_public.to_bytes(256, "big")
    try:
        Ed25519PublicKey.from_public_bytes(server_public_raw).verify(signature, message)
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# 6) Wire framing - length-prefixed JSON messages
# ---------------------------------------------------------------------------
# A real TLS record has a binary header; to keep the walkthrough readable we
# send each handshake message as JSON with a 4-byte big-endian length prefix.
# Integers that do not fit in JSON safely (DH values, keys) are hex-encoded.


def send_message(sock: socket.socket, obj: dict) -> bytes:
    """Serialize `obj` to JSON, length-prefix it, and send. Returns raw bytes."""
    payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    sock.sendall(struct.pack(">I", len(payload)) + payload)
    return payload


def recv_message(sock: socket.socket) -> tuple[dict, bytes]:
    """Receive one length-prefixed JSON message. Returns (obj, raw_bytes)."""
    header = _recv_exact(sock, 4)
    (length,) = struct.unpack(">I", header)
    payload = _recv_exact(sock, length)
    return json.loads(payload.decode("utf-8")), payload


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes or raise if the connection closes early."""
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("Connection closed before message was complete")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


# ---------------------------------------------------------------------------
# 7) Small helpers
# ---------------------------------------------------------------------------


def new_random() -> bytes:
    """A fresh 32-byte handshake random (client_random / server_random)."""
    return os.urandom(RANDOM_LEN)


def to_hex(data: bytes, head: int = 16) -> str:
    """Short hex preview for logging, e.g. 'a1b2c3...(32B)'."""
    h = data.hex()
    if len(data) <= head:
        return h
    return f"{h[: head * 2]}...({len(data)}B)"


@dataclass
class Logger:
    """Tiny step logger so the handshake reads as a numbered walkthrough."""

    role: str
    step: int = field(default=0)

    def log(self, message: str) -> None:
        self.step += 1
        print(f"[{self.role}] {self.step:>2}. {message}", flush=True)

    def note(self, message: str) -> None:
        print(f"[{self.role}]     {message}", flush=True)
