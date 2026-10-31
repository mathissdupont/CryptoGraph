import os
from Crypto.Cipher import AES


def choose_key(use_random):
    if use_random:
        return os.urandom(16)
    return b"0123456789abcdef"


def build_cipher(flag):
    key = choose_key(flag)
    return AES.new(key, AES.MODE_ECB)
