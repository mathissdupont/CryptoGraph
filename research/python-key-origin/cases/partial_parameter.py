import os
from Crypto.Cipher import AES


def build_cipher(use_random, supplied):
    key = os.urandom(16) if use_random else supplied
    return AES.new(key, AES.MODE_ECB)
