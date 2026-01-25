import time
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa, x25519
from cryptography.hazmat.backends import default_backend


# -----------------------------
# PQC (Simulated Kyber Hybrid)
# -----------------------------
def get_pqc_metrics():
    t0 = time.perf_counter()
    shared = secrets.token_bytes(32)
    t1 = time.perf_counter()

    t2 = time.perf_counter()
    ct = secrets.token_bytes(768)
    t3 = time.perf_counter()

    t4 = time.perf_counter()
    secrets.token_bytes(32)
    t5 = time.perf_counter()

    return {
        "algorithm": "CRYSTALS-Kyber (Simulated)",
        "category": "PQC (Lattice)",
        "security_level": "NIST L1",
        "quantum_resistance": "✔ Safe vs Quantum",
        "public_key_size": "800 bytes",
        "ciphertext_size": "768 bytes",
        "shared_secret_size": "32 bytes",
        "keygen_ms": round((t1 - t0) * 1000, 4),
        "encap_ms": round((t3 - t2) * 1000, 4),
        "decap_ms": round((t5 - t4) * 1000, 4),
    }


# -----------------------------
# RSA (Classical)
# -----------------------------
def get_rsa_metrics():
    t0 = time.perf_counter()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    t1 = time.perf_counter()

    pub = key.public_key().public_bytes(
        encoding=3,
        format=0
    )

    return {
        "algorithm": "RSA-2048",
        "category": "Classical Integer Factorization",
        "security_level": "112-bit",
        "quantum_resistance": "✘ Broken by Shor",
        "public_key_size": f"{len(pub)} bytes",
        "keygen_ms": round((t1 - t0) * 1000, 4),
        "encrypt_ms": "~ dependent on padding",
        "decrypt_ms": "~ dependent on CRT",
    }


# -----------------------------
# ECDH (X25519)
# -----------------------------
def get_ecdh_metrics():
    t0 = time.perf_counter()
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    t1 = time.perf_counter()

    t2 = time.perf_counter()
    peer = x25519.X25519PrivateKey.generate().public_key()
    shared = priv.exchange(peer)
    t3 = time.perf_counter()

    return {
        "algorithm": "X25519 (ECDH)",
        "category": "Classical Elliptic Curve",
        "security_level": "128-bit",
        "quantum_resistance": "✘ Broken by Shor",
        "public_key_size": "32 bytes",
        "shared_secret_size": f"{len(shared)} bytes",
        "keygen_ms": round((t1 - t0) * 1000, 4),
        "exchange_ms": round((t3 - t2) * 1000, 4),
    }
