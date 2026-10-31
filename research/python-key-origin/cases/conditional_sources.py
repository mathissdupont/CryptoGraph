import os
from Crypto.Cipher import AES


def build_cipher(use_random):
    key = os.urandom(16) if use_random else b"0123456789abcdef"
    return AES.new(key, AES.MODE_ECB)
