import os
from Crypto.Cipher import AES


def build_cipher():
    unused_random = os.urandom(16)
    key = b"0123456789abcdef"
    return AES.new(key, AES.MODE_ECB)
