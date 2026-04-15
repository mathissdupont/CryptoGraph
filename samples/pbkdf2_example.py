import hashlib
import secrets


def derive_password_key(password):
    salt = secrets.token_bytes(16)
    return hashlib.pbkdf2_hmac("sha256", password, salt, 100_000)

