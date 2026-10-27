import os
from Crypto.Cipher import AES


def build_cipher():
    rng = os.urandom
    key = rng(16)
    return AES.new(key, AES.MODE_ECB)
