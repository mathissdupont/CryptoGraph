import secrets
from cryptography.hazmat.primitives.ciphers import algorithms


def build_cipher():
    key = secrets.token_bytes(16)
    return algorithms.AES(key)
