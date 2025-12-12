# gen_keys.py
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import secrets, base64

priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub  = priv.public_key()

with open("rsa_private.pem","wb") as f:
    f.write(priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))
with open("rsa_public.pem","wb") as f:
    f.write(pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

hmac_key = secrets.token_bytes(32)
print("Wrote rsa_private.pem / rsa_public.pem")
print("Set env HMAC_SECRET to (base64):", base64.b64encode(hmac_key).decode("ascii"))
