from cryptography.hazmat.primitives.ciphers import algorithms


def build_cipher():
    key = b"0123456789abcdef"
    return algorithms.AES(key)
