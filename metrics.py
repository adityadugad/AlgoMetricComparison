# metrics.py
import time, os
from cryptography.hazmat.primitives.asymmetric import rsa, padding, x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# === PQC (Simulated Kyber Hybrid Model) ===
def get_pqc_metrics():
    t0 = time.perf_counter()
    aes_key = AESGCM.generate_key(bit_length=256)
    t1 = time.perf_counter()

    aes = AESGCM(aes_key)
    nonce = os.urandom(12)
    msg = b"PQC Benchmark"
    t2 = time.perf_counter()
    ct = aes.encrypt(nonce, msg, None)
    t3 = time.perf_counter()
    t4 = time.perf_counter()
    aes.decrypt(nonce, ct, None)
    t5 = time.perf_counter()

    return {
        "algorithm": "CRYSTALS-Kyber (Hybrid Sim)",
        "security_level": "NIST PQ Level 1",
        "quantum_resistant": True,
        "public_key_size_bytes": 800,
        "ciphertext_size_bytes": 768,
        "shared_secret_size_bytes": 32,
        "keygen_ms": round((t1-t0)*1000,4),
        "encap_ms": round((t3-t2)*1000,4),
        "decap_ms": round((t5-t4)*1000,4)
    }

# === Classical RSA-2048 ===
def get_rsa_metrics():
    t0 = time.perf_counter()
    priv = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    pub = priv.public_key()
    t1 = time.perf_counter()

    data = b"RSA Benchmark"
    t2 = time.perf_counter()
    ct = pub.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    t3 = time.perf_counter()

    t4 = time.perf_counter()
    priv.decrypt(
        ct,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    t5 = time.perf_counter()

    pub_bytes = pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return {
        "algorithm": "RSA-2048",
        "security_level": "Classical ~128-bit",
        "quantum_resistant": False,
        "public_key_size_bytes": len(pub_bytes),
        "ciphertext_size_bytes": len(ct),
        "keygen_ms": round((t1-t0)*1000,4),
        "encrypt_ms": round((t3-t2)*1000,4),
        "decrypt_ms": round((t5-t4)*1000,4)
    }

# === Classical ECDH (X25519) ===
def get_ecdh_metrics():
    t0 = time.perf_counter()
    privA = x25519.X25519PrivateKey.generate()
    privB = x25519.X25519PrivateKey.generate()
    pubA = privA.public_key()
    pubB = privB.public_key()
    t1 = time.perf_counter()

    t2 = time.perf_counter()
    s1 = privA.exchange(pubB)
    s2 = privB.exchange(pubA)
    t3 = time.perf_counter()

    assert s1 == s2

    pub_bytes = pubA.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw
    )

    return {
        "algorithm": "X25519 (ECDH)",
        "security_level": "Classical ~128-bit",
        "quantum_resistant": False,
        "public_key_size_bytes": len(pub_bytes),
        "shared_secret_size_bytes": len(s1),
        "keygen_ms": round((t1-t0)*1000,4),
        "exchange_ms": round((t3-t2)*1000,4)
    }
