import os
from Crypto.Cipher import AES


def build_cipher():
    return AES.new(key=os.urandom(16), mode=AES.MODE_ECB)
