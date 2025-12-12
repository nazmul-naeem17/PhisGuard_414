# crypto_utils.py
import os, json, base64, secrets, time
from typing import Tuple, Dict
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.hmac import HMAC

# --- helpers ---
def b64(x: bytes) -> str:
    return base64.b64encode(x).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def canonical_bytes(payload: dict) -> bytes:
    # Sort keys; compact separators to match clients
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

# --- key loading/generation ---
def load_or_make_hmac_key() -> bytes:
    k = os.getenv("HMAC_SECRET", "").strip()
    if k:
        # accept base64 or hex
        try:
            return base64.b64decode(k)
        except Exception:
            return bytes.fromhex(k)
    return secrets.token_bytes(32)

def load_or_make_rsa() -> Tuple[object, object, str]:
    priv_path = os.getenv("RSA_PRIV_PEM", "").strip()
    pub_path  = os.getenv("RSA_PUB_PEM", "").strip()
    if priv_path and os.path.exists(priv_path):
        with open(priv_path, "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)
        if pub_path and os.path.exists(pub_path):
            with open(pub_path, "rb") as f:
                pub = serialization.load_pem_public_key(f.read())
        else:
            pub = priv.public_key()
    else:
        # ephemeral for dev
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub  = priv.public_key()

    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return priv, pub, pub_pem

# --- MAC + signature ---
def sign_and_mac(payload: dict, hmac_key: bytes, rsa_priv) -> Dict[str, str]:
    msg = canonical_bytes(payload)

    # HMAC for integrity+replay protection with shared secret
    h = HMAC(hmac_key, hashes.SHA256())
    h.update(msg)
    hmac_b64 = b64(h.finalize())

    # RSA PKCS#1 v1.5 + SHA-256 for public verification
    sig = rsa_priv.sign(msg, padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = b64(sig)
    return {"hmac": hmac_b64, "signature": sig_b64}

def verify_rsa(pub_pem: str, payload: dict, signature_b64: str) -> bool:
    try:
        pub = serialization.load_pem_public_key(pub_pem.encode("utf-8"))
        sig = b64d(signature_b64)
        pub.verify(sig, canonical_bytes(payload), padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False
