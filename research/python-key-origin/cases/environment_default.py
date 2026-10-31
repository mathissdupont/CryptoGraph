import os
from Crypto.Cipher import AES


def build_cipher():
    key = os.getenv("CRYPTOGRAPH_TEST_KEY", "0123456789abcdef").encode()
    return AES.new(key, AES.MODE_ECB)
