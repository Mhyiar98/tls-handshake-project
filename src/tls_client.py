"""
tls_client.py
=================
The client side of the simplified TLS-style handshake.

Run it (after starting tls_server.py):

    python3 src/tls_client.py --port 8443                       # insecure
    python3 src/tls_client.py --port 8443 --secure \
            --pin-key <hex>                                     # authenticated

In secure mode the client verifies the server's Ed25519 signature over the
DH public key against a pinned public key. If the key does not match (as it
would not for a man-in-the-middle), the client ABORTS the handshake.

Author: Mihyar Al-Taher Al-Mustiri
"""

from __future__ import annotations

import argparse
import socket
import sys

from tls_common import (
    CIPHER_SUITE,
    PROTOCOL_VERSION,
    DHKeyPair,
    Logger,
    RecordCrypter,
    Transcript,
    derive_session_keys,
    finished_mac,
    new_random,
    recv_message,
    send_message,
    to_hex,
    verify_dh_signature,
)


class HandshakeError(Exception):
    """Raised when the client aborts the handshake (e.g. bad signature)."""


def run_client_handshake(
    conn: socket.socket, secure: bool, pinned_server_key: bytes | None
) -> None:
    """Perform one full handshake from the client side."""
    log = Logger("CLIENT")
    transcript = Transcript()

    # --- Step 1: send ClientHello ---------------------------------------
    client_random = new_random()
    client_hello = {
        "type": "client_hello",
        "version": PROTOCOL_VERSION,
        "client_random": client_random.hex(),
        "cipher_suites": [CIPHER_SUITE],
    }
    raw = send_message(conn, client_hello)
    transcript.add(raw)
    log.log("Sent ClientHello")
    log.note(f"client_random = {to_hex(client_random)}")

    # --- Step 2: receive ServerHello ------------------------------------
    server_hello, raw = recv_message(conn)
    if server_hello.get("type") == "alert":
        raise HandshakeError(f"Server alert: {server_hello.get('reason')}")
    transcript.add(raw)
    server_random = bytes.fromhex(server_hello["server_random"])
    server_dh_public = int.from_bytes(bytes.fromhex(server_hello["dh_public"]), "big")
    log.log("Received ServerHello")
    log.note(f"server_random = {to_hex(server_random)}")
    log.note(f"chosen suite = {server_hello['cipher_suite']}")

    # --- Step 2b: authenticate the server (secure mode only) ------------
    if secure:
        if "dh_signature" not in server_hello or "server_pubkey" not in server_hello:
            raise HandshakeError("Server did not authenticate (no signature)")
        presented_key = bytes.fromhex(server_hello["server_pubkey"])
        signature = bytes.fromhex(server_hello["dh_signature"])

        # (a) The presented key must be the one we trust (pinning).
        if pinned_server_key is not None and presented_key != pinned_server_key:
            raise HandshakeError(
                "Server public key does not match pinned key - possible MITM!"
            )
        # (b) The signature over the DH public key must be valid.
        if not verify_dh_signature(
            presented_key, client_random, server_random, server_dh_public, signature
        ):
            raise HandshakeError("Invalid server signature - possible MITM!")
        log.log("Verified server signature + pinned key (server authenticated)")

    # --- Step 3: send ClientKeyExchange ---------------------------------
    client_dh = DHKeyPair.generate()
    raw = send_message(
        conn,
        {"type": "client_key_exchange", "dh_public": client_dh.public.to_bytes(256, "big").hex()},
    )
    transcript.add(raw)
    log.log("Sent ClientKeyExchange (g^a mod p)")
    log.note(f"client DH public = {to_hex(client_dh.public.to_bytes(256, 'big'))}")

    # --- Step 4: derive session keys ------------------------------------
    shared_secret = client_dh.shared_secret(server_dh_public)
    keys = derive_session_keys(shared_secret, client_random, server_random)
    log.log("Derived session keys via HKDF-SHA256")
    log.note(f"shared secret = {to_hex(shared_secret)}")

    server_reader = RecordCrypter(keys.server_write_key)   # decrypt server data
    client_writer = RecordCrypter(keys.client_write_key)   # encrypt our data

    # --- Step 5: Finished exchange --------------------------------------
    client_finished_mac = finished_mac(
        keys.master_secret, transcript.digest(), b"client finished"
    )
    raw = send_message(conn, {"type": "finished", "mac": client_finished_mac.hex()})
    transcript.add(raw)
    log.log("Sent client Finished MAC")

    server_finished, _ = recv_message(conn)
    if server_finished.get("type") == "alert":
        raise HandshakeError(f"Server alert: {server_finished.get('reason')}")
    expected = finished_mac(keys.master_secret, transcript.digest(), b"server finished")
    if bytes.fromhex(server_finished["mac"]) != expected:
        raise HandshakeError("Server Finished MAC mismatch - transcript tampered!")
    log.log("Verified server Finished MAC -> handshake COMPLETE")

    # --- Step 6: application data (encrypted) ----------------------------
    message = "Mihyar"
    record = client_writer.encrypt(message.encode())
    send_message(conn, {"type": "app_data", "record": record.hex()})
    log.log(f"Sent encrypted application data: {message!r}")

    encrypted_reply, _ = recv_message(conn)
    reply = server_reader.decrypt(bytes.fromhex(encrypted_reply["record"]))
    log.log("Received + decrypted server reply")
    log.note(f"server said: {reply.decode()!r}")


def connect(host: str, port: int, secure: bool, pinned_key_hex: str | None) -> None:
    pinned = bytes.fromhex(pinned_key_hex) if pinned_key_hex else None
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        try:
            run_client_handshake(sock, secure, pinned)
        except HandshakeError as exc:
            print(f"\n[CLIENT] !! HANDSHAKE ABORTED: {exc}", flush=True)
            sys.exit(2)


def main() -> None:
    parser = argparse.ArgumentParser(description="Simplified TLS-style client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--secure", action="store_true", help="require server auth")
    parser.add_argument(
        "--pin-key",
        default=None,
        help="hex of the server's trusted Ed25519 public key (secure mode)",
    )
    args = parser.parse_args()
    connect(args.host, args.port, args.secure, args.pin_key)


if __name__ == "__main__":
    main()
