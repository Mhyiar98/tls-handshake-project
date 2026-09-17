# TLS Handshake Walkthrough — Simplified Client/Server over Sockets

**Information Security — Semester Project (Summer 2026)**
**Student:** Mihyar Al-Taher Al-Mustiri
**Instructor:** Ms. Nada Salaheddin Gheriyani
**Security area:** Network security protocol · **Tools:** Python 3 + sockets + `cryptography`

---

## 1. What this project is

A from-scratch, readable implementation of a **TLS-style handshake** between a
client and a server over local TCP sockets. It walks through the four ideas at
the heart of transport security:

1. **Hello exchange** — `ClientHello` / `ServerHello` with 32-byte randoms and a
   negotiated cipher suite.
2. **Key exchange** — ephemeral **Diffie-Hellman** (RFC 3526, 2048-bit MODP
   group) so `g^a mod p` is visible in plain Python.
3. **Session-key derivation** — **HKDF-SHA256** turns the DH shared secret into
   directional AES-256 traffic keys, salted with both randoms.
4. **Encrypted channel** — application data is protected with **AES-256-GCM**,
   and a **Finished** HMAC over the full transcript proves nothing was tampered.

It then does what a security project must: it **attacks itself**. An included
man-in-the-middle (MITM) tool defeats the *unauthenticated* handshake and reads
all traffic — after which an **authenticated** variant (Ed25519-signed key
exchange + key pinning) is added and the same attack is shown to **fail**.

> ⚠️ **Ethics & legality.** Everything runs on `127.0.0.1` (loopback) against a
> lab server that this project owns. No external host is ever contacted. The
> MITM code exists to demonstrate a weakness and then prove the fix — the exact
> discipline required by the assignment's ethics section.

---

## 2. Repository layout

```
tls-handshake-project/
├── src/
│   ├── tls_common.py     # DH group, HKDF, AES-GCM, transcript, Ed25519, framing
│   ├── tls_server.py     # server side (--secure enables authentication)
│   ├── tls_client.py     # client side (--secure requires + pins server key)
│   ├── mitm.py           # man-in-the-middle attacker (lab only)
│   └── run_demo.py       # one-command driver: all 4 scenarios end to end
├── tests/
│   └── test_handshake.py # 5 self-tests proving the security properties
├── docs/evidence/
│   └── demo_output.txt   # captured transcript used as report evidence
├── report/               # 6-page technical report (.docx)
├── slides/               # presentation (.pptx)
├── requirements.txt
└── README.md
```

## 3. How to run

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 3a. The full guided demo (recommended)

```bash
python3 src/run_demo.py
```

This prints four labelled scenarios:

| # | Scenario | Expected result |
|---|----------|-----------------|
| 1 | Normal handshake, insecure | Succeeds; data is AES-256-GCM encrypted |
| 2 | MITM vs. insecure handshake | Attacker **decrypts everything** |
| 3 | MITM vs. authenticated handshake | Client **aborts** — attack defeated |
| 4 | Normal handshake, authenticated | Works normally (fix is non-breaking) |

### 3b. Manual, two-terminal run

```bash
# terminal 1 — insecure
python3 src/tls_server.py --port 8443
# terminal 2
python3 src/tls_client.py --port 8443
```

```bash
# authenticated (hardened) — the client pins the server's public key
python3 src/tls_server.py --port 8443 --secure
python3 src/tls_client.py --port 8443 --secure --pin-key <server_public_key_hex>
```

### 3c. Tests

```bash
python3 tests/test_handshake.py     # or: pytest tests/
```

## 4. Findings at a glance

| ID | Finding | Severity | Fix (shipped) |
|----|---------|----------|---------------|
| F-01 | Unauthenticated key exchange → full MITM | **Critical** | Ed25519-signed DH key + client pinning (`--secure`) |
| F-02 | No transcript binding would allow message tampering | High | HMAC **Finished** over SHA-256 transcript |
| F-03 | Static keys would break forward secrecy | Medium | **Ephemeral** DH key pair per session |
| F-04 | GCM nonce reuse would be catastrophic | Medium | Per-record incrementing sequence-number nonce |

Full write-up, CVSS reasoning and evidence are in the 6-page report.

## 5. Honest limitations

This is a teaching model, not a production stack. It does **not** implement X.509
certificates/PKI (it pins a raw key instead), TLS 1.3 record padding, session
resumption, or downgrade-protection across multiple cipher suites, and it uses
finite-field DH rather than X25519. These are called out in the report's
limitations section.
