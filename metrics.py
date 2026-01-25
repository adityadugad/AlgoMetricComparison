import time
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa, x25519, padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


# ----------------------------- PQC (Simulated Kyber) -----------------------------
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
        "security_level": "NIST Level 1",
        "quantum": "✔ Safe vs Quantum",
        "public_key": "800 bytes",
        "ciphertext": "768 bytes",
        "shared_secret": "32 bytes",
        "keygen_ms": round((t1-t0)*1000, 4),
        "encap_ms": round((t3-t2)*1000, 4),
        "decap_ms": round((t5-t4)*1000, 4),
    }


# ----------------------------- RSA-2048 -----------------------------
def get_rsa_metrics():
    t0 = time.perf_counter()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    t1 = time.perf_counter()

    pub = key.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )

    t2 = time.perf_counter()
    ct = key.public_key().encrypt(
        b"benchmark-test",
        padding.PKCS1v15()
    )
    t3 = time.perf_counter()

    t4 = time.perf_counter()
    key.decrypt(ct, padding.PKCS1v15())
    t5 = time.perf_counter()

    return {
        "algorithm": "RSA-2048",
        "category": "Integer Factorization",
        "security_level": "112-bit",
        "quantum": "✘ Broken by Shor",
        "public_key": f"{len(pub)} bytes",
        "keygen_ms": round((t1-t0)*1000, 4),
        "encrypt_ms": round((t3-t2)*1000, 4),
        "decrypt_ms": round((t5-t4)*1000, 4),
    }


# ----------------------------- X25519 ECDH -----------------------------
def get_ecdh_metrics():
    t0 = time.perf_counter()
    priv = x25519.X25519PrivateKey.generate()
    peer = x25519.X25519PrivateKey.generate().public_key()
    t1 = time.perf_counter()

    t2 = time.perf_counter()
    shared = priv.exchange(peer)
    t3 = time.perf_counter()

    return {
        "algorithm": "X25519 (ECDH)",
        "category": "Elliptic Curve Diffie-Hellman",
        "security_level": "128-bit",
        "quantum": "✘ Broken by Shor",
        "public_key": "32 bytes",
        "shared_secret": f"{len(shared)} bytes",
        "keygen_ms": round((t1-t0)*1000, 4),
        "exchange_ms": round((t3-t2)*1000, 4),
    }
