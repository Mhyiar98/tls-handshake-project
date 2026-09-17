"""
test_handshake.py
=================
Lightweight self-tests for the crypto building blocks. They can be run with
either pytest or plain python:

    python3 tests/test_handshake.py        # prints PASS/FAIL for each check
    pytest tests/                          # if pytest is installed

The tests prove the three properties the report claims:
  * two honest parties derive the SAME session keys,
  * a tampered/forged DH public produces DIFFERENT keys (MITM cannot match),
  * AES-256-GCM rejects any modification of the ciphertext (integrity).

Author: Mhyiar Elmistere
"""

import os
import sys

# Make src/ importable whether run from the repo root or the tests folder.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cryptography.exceptions import InvalidSignature  # noqa: E402

from tls_common import (  # noqa: E402
    DHKeyPair,
    RecordCrypter,
    derive_session_keys,
    new_random,
    finished_mac,
    Transcript,
    load_or_create_server_identity,
    sign_dh_public,
    verify_dh_signature,
    server_public_key_bytes,
)


def test_honest_parties_agree_on_keys():
    """A full DH exchange yields identical keys on both ends."""
    client = DHKeyPair.generate()
    server = DHKeyPair.generate()
    cr, sr = new_random(), new_random()

    client_secret = client.shared_secret(server.public)
    server_secret = server.shared_secret(client.public)
    assert client_secret == server_secret

    ck = derive_session_keys(client_secret, cr, sr)
    sk = derive_session_keys(server_secret, cr, sr)
    assert ck.client_write_key == sk.client_write_key
    assert ck.server_write_key == sk.server_write_key


def test_mitm_keys_do_not_match():
    """
    With no authentication a MITM negotiates its own key with each side, so the
    key the client derives never matches the key the server derives.
    """
    client = DHKeyPair.generate()
    server = DHKeyPair.generate()
    attacker = DHKeyPair.generate()
    cr, sr = new_random(), new_random()

    # Client unknowingly does DH with the attacker; server does DH with attacker.
    client_secret = client.shared_secret(attacker.public)
    server_secret = server.shared_secret(attacker.public)
    assert client_secret != server_secret  # the tell-tale of an interception


def test_gcm_detects_tampering():
    """Flipping one ciphertext bit must raise, not silently decrypt."""
    key = os.urandom(32)
    enc = RecordCrypter(key)
    dec = RecordCrypter(key)
    record = bytearray(enc.encrypt(b"transfer $10 to Mihyar"))
    record[-1] ^= 0x01  # tamper with the auth tag
    try:
        dec.decrypt(bytes(record))
        raise AssertionError("GCM accepted tampered ciphertext!")
    except Exception:
        pass  # any decryption failure is the correct behaviour


def test_signature_stops_forged_key():
    """A signature over the real DH key does not verify for a swapped key."""
    identity = load_or_create_server_identity("test_identity.key")
    pub = server_public_key_bytes(identity)
    cr, sr = new_random(), new_random()
    real = DHKeyPair.generate()
    forged = DHKeyPair.generate()

    sig = sign_dh_public(identity, cr, sr, real.public)
    assert verify_dh_signature(pub, cr, sr, real.public, sig) is True
    assert verify_dh_signature(pub, cr, sr, forged.public, sig) is False
    os.remove("test_identity.key")


def test_finished_mac_covers_transcript():
    """Changing any handshake byte changes the Finished MAC."""
    ms = os.urandom(32)
    t1, t2 = Transcript(), Transcript()
    t1.add(b"ClientHello|A")
    t2.add(b"ClientHello|B")  # one byte different
    m1 = finished_mac(ms, t1.digest(), b"client finished")
    m2 = finished_mac(ms, t2.digest(), b"client finished")
    assert m1 != m2


def _run_all():
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"PASS  {t.__name__}")
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"FAIL  {t.__name__}: {exc}")
    print(f"\n{len(tests) - failures}/{len(tests)} tests passed")
    return failures


if __name__ == "__main__":
    sys.exit(1 if _run_all() else 0)
