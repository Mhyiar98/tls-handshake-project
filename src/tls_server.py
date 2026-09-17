"""
tls_server.py
=================
The server side of the simplified TLS-style handshake.

Run it standalone in one terminal:

    python3 src/tls_server.py --port 8443              # insecure (no auth)
    python3 src/tls_server.py --port 8443 --secure     # authenticated server

Then run tls_client.py in a second terminal.

Handshake performed here (server view):
    1. Receive ClientHello       (client_random + supported suites)
    2. Send ServerHello          (server_random + chosen suite + DH public
                                  [+ Ed25519 signature over it in secure mode])
    3. Receive ClientKeyExchange (client DH public)
    4. Derive session keys       (DH shared secret -> HKDF -> AES keys)
    5. Exchange Finished MACs     (verify the whole transcript)
    6. Exchange encrypted data    (AES-256-GCM application records)

Author: Mhyiar Elmistere
"""

from __future__ import annotations

import argparse
import socket

from tls_common import (
    CIPHER_SUITE,
    PROTOCOL_VERSION,
    DHKeyPair,
    Logger,
    RecordCrypter,
    Transcript,
    derive_session_keys,
    finished_mac,
    load_or_create_server_identity,
    new_random,
    recv_message,
    send_message,
    server_public_key_bytes,
    sign_dh_public,
    to_hex,
)

IDENTITY_PATH = "server_identity.key"


def run_server_handshake(conn: socket.socket, secure: bool) -> None:
    """Perform one full handshake on an already-accepted connection."""
    log = Logger("SERVER")
    transcript = Transcript()

    # --- Step 1: receive ClientHello ------------------------------------
    client_hello, raw = recv_message(conn)
    transcript.add(raw)
    client_random = bytes.fromhex(client_hello["client_random"])
    log.log("Received ClientHello")
    log.note(f"client_random = {to_hex(client_random)}")
    log.note(f"offered suites = {client_hello['cipher_suites']}")

    if CIPHER_SUITE not in client_hello["cipher_suites"]:
        send_message(conn, {"type": "alert", "reason": "no shared cipher suite"})
        raise RuntimeError("Handshake failed: no shared cipher suite")

    # --- Step 2: send ServerHello (+ ephemeral DH public [+ signature]) --
    server_random = new_random()
    server_dh = DHKeyPair.generate()
    log.log("Generated ephemeral DH key pair (g^b mod p)")
    log.note(f"server DH public = {to_hex(server_dh.public.to_bytes(256, 'big'))}")

    server_hello = {
        "type": "server_hello",
        "version": PROTOCOL_VERSION,
        "server_random": server_random.hex(),
        "cipher_suite": CIPHER_SUITE,
        "dh_public": server_dh.public.to_bytes(256, "big").hex(),
        "authenticated": secure,
    }

    if secure:
        # Hardened mode: authenticate the server by signing its DH public key
        # with a long-term Ed25519 key. The client pins/verifies this key,
        # which is what stops a man-in-the-middle.
        identity = load_or_create_server_identity(IDENTITY_PATH)
        signature = sign_dh_public(
            identity, client_random, server_random, server_dh.public
        )
        server_hello["server_pubkey"] = server_public_key_bytes(identity).hex()
        server_hello["dh_signature"] = signature.hex()
        log.note("secure mode: signed DH public key with long-term Ed25519 key")

    raw = send_message(conn, server_hello)
    transcript.add(raw)
    log.log("Sent ServerHello" + (" (authenticated)" if secure else " (UNauthenticated)"))

    # --- Step 3: receive ClientKeyExchange ------------------------------
    client_kx, raw = recv_message(conn)
    transcript.add(raw)
    client_dh_public = int.from_bytes(bytes.fromhex(client_kx["dh_public"]), "big")
    log.log("Received ClientKeyExchange")
    log.note(f"client DH public = {to_hex(client_dh_public.to_bytes(256, 'big'))}")

    # --- Step 4: derive session keys ------------------------------------
    shared_secret = server_dh.shared_secret(client_dh_public)
    keys = derive_session_keys(shared_secret, client_random, server_random)
    log.log("Derived session keys via HKDF-SHA256")
    log.note(f"shared secret = {to_hex(shared_secret)}")
    log.note(f"client_write_key = {to_hex(keys.client_write_key, 32)}")
    log.note(f"server_write_key = {to_hex(keys.server_write_key, 32)}")

    client_reader = RecordCrypter(keys.client_write_key)   # decrypt client data
    server_writer = RecordCrypter(keys.server_write_key)   # encrypt our data

    # --- Step 5: Finished exchange (verify transcript) ------------------
    client_finished, raw = recv_message(conn)
    expected = finished_mac(keys.master_secret, transcript.digest(), b"client finished")
    if bytes.fromhex(client_finished["mac"]) != expected:
        send_message(conn, {"type": "alert", "reason": "bad client Finished"})
        raise RuntimeError("Handshake failed: client Finished MAC mismatch")
    transcript.add(raw)
    log.log("Verified client Finished MAC (transcript intact)")

    server_finished_mac = finished_mac(
        keys.master_secret, transcript.digest(), b"server finished"
    )
    send_message(conn, {"type": "finished", "mac": server_finished_mac.hex()})
    log.log("Sent server Finished MAC -> handshake COMPLETE")

    # --- Step 6: application data (encrypted) ----------------------------
    encrypted_request, _ = recv_message(conn)
    request = client_reader.decrypt(bytes.fromhex(encrypted_request["record"]))
    log.log("Received encrypted application data")
    log.note(f"decrypted client message: {request.decode()!r}")

    reply = f"Hello {request.decode()} - this channel is AES-256-GCM encrypted."
    record = server_writer.encrypt(reply.encode())
    send_message(conn, {"type": "app_data", "record": record.hex()})
    log.log("Sent encrypted reply -> session closing")


def serve(host: str, port: int, secure: bool, ready=None) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(1)
        mode = "SECURE (authenticated)" if secure else "INSECURE (no server auth)"
        print(f"[SERVER] listening on {host}:{port}  mode={mode}\n", flush=True)
        if ready is not None:
            ready.set()          # signal the driver that accept() is ready
        conn, addr = srv.accept()
        with conn:
            print(f"[SERVER] connection from {addr}\n", flush=True)
            try:
                run_server_handshake(conn, secure)
            except (ConnectionError, RuntimeError) as exc:
                # A peer (or a MITM whose victim aborted) dropped the link.
                print(f"[SERVER] session ended early: {exc}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Simplified TLS-style server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument(
        "--secure",
        action="store_true",
        help="authenticate the server by signing its DH public key (Ed25519)",
    )
    args = parser.parse_args()
    serve(args.host, args.port, args.secure)


if __name__ == "__main__":
    main()
