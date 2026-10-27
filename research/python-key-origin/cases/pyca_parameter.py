from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def build_cipher(key):
    return AESGCM(key)
