import os
from Crypto.Cipher import AES


def build_cipher(repeat):
    key = b"0123456789abcdef"
    while repeat:
        key = os.urandom(16)
    return AES.new(key, AES.MODE_ECB)
