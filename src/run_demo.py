"""
run_demo.py
=================
One-command driver that runs the whole story end to end and prints it as a
labelled transcript. This is what generates the evidence used in the report
and the recorded clip used in the presentation.

    python3 src/run_demo.py

Three scenarios, in order:

    SCENARIO 1  Normal handshake (insecure)      -> succeeds, data encrypted
    SCENARIO 2  MITM attack     (insecure)       -> attacker DECRYPTS everything
    SCENARIO 3  MITM attack     (secure/hardened)-> client ABORTS, attack fails
    SCENARIO 4  Normal handshake (secure)        -> fix does not break normal use

Everything runs on 127.0.0.1 loopback only. No external network is touched.

Author: Mihyar Al-Taher Al-Mustiri
"""

from __future__ import annotations

import os
import socket
import threading
import time

from tls_client import connect as client_connect
from tls_server import serve as server_serve, IDENTITY_PATH
from mitm import run_mitm
from tls_common import load_or_create_server_identity, server_public_key_bytes


def _banner(title: str) -> None:
    print("\n" + "=" * 72)
    print(f"  {title}")
    print("=" * 72, flush=True)


def scenario_normal(port: int, secure: bool, pin_key_hex: str | None) -> None:
    server_ready = threading.Event()
    server_thread = threading.Thread(
        target=server_serve, args=("127.0.0.1", port, secure, server_ready), daemon=True
    )
    server_thread.start()
    server_ready.wait(timeout=5)
    time.sleep(0.05)             # let accept() actually block before we connect
    client_thread = threading.Thread(
        target=_safe_client, args=("127.0.0.1", port, secure, pin_key_hex), daemon=True
    )
    client_thread.start()
    client_thread.join(timeout=10)
    server_thread.join(timeout=2)


def scenario_mitm(server_port: int, mitm_port: int, secure: bool, pin_key_hex: str | None) -> None:
    server_ready = threading.Event()
    server_thread = threading.Thread(
        target=server_serve, args=("127.0.0.1", server_port, secure, server_ready), daemon=True
    )
    server_thread.start()
    server_ready.wait(timeout=5)

    mitm_ready = threading.Event()
    mitm_thread = threading.Thread(
        target=run_mitm,
        args=("127.0.0.1", mitm_port, "127.0.0.1", server_port, mitm_ready),
        daemon=True,
    )
    mitm_thread.start()
    mitm_ready.wait(timeout=5)
    time.sleep(0.05)

    # The victim client connects to the MITM port, believing it is the server.
    client_thread = threading.Thread(
        target=_safe_client, args=("127.0.0.1", mitm_port, secure, pin_key_hex), daemon=True
    )
    client_thread.start()
    client_thread.join(timeout=10)
    mitm_thread.join(timeout=3)
    server_thread.join(timeout=2)


def _safe_client(host: str, port: int, secure: bool, pin_key_hex: str | None) -> None:
    """Run the client but turn its sys.exit into a printed line for the demo."""
    try:
        client_connect(host, port, secure, pin_key_hex)
    except SystemExit:
        pass


def main() -> None:
    # Make sure the server identity exists so we can pin its public key.
    identity = load_or_create_server_identity(IDENTITY_PATH)
    pin_key_hex = server_public_key_bytes(identity).hex()

    _banner("SCENARIO 1 - Normal handshake, INSECURE mode (baseline)")
    print("Expected: handshake completes, application data is AES-256-GCM encrypted.\n")
    scenario_normal(port=9001, secure=False, pin_key_hex=None)

    _banner("SCENARIO 2 - MITM attack against the INSECURE handshake")
    print("Expected: the attacker sits in the middle and reads all 'encrypted' traffic.\n")
    scenario_mitm(server_port=9002, mitm_port=9102, secure=False, pin_key_hex=None)

    _banner("SCENARIO 3 - MITM attack against the SECURE (authenticated) handshake")
    print("Expected: the client detects the forged key and ABORTS. Attack defeated.\n")
    scenario_mitm(server_port=9003, mitm_port=9103, secure=True, pin_key_hex=pin_key_hex)

    _banner("SCENARIO 4 - Normal handshake, SECURE mode (fix keeps normal use working)")
    print("Expected: authenticated handshake completes normally for the honest client.\n")
    scenario_normal(port=9004, secure=True, pin_key_hex=pin_key_hex)

    _banner("DEMO COMPLETE")
    print(f"Server identity (pinned Ed25519 public key): {pin_key_hex}")
    print("Summary: authentication of the key exchange is what stops the MITM.\n")


if __name__ == "__main__":
    # Run from the src/ directory so imports resolve without packaging.
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    main()
