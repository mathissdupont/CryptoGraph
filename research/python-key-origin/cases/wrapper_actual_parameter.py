import os
from Crypto.Cipher import AES


def identity_key(value):
    return value


def build_cipher():
    key = identity_key(os.urandom(16))
    return AES.new(key, AES.MODE_ECB)
