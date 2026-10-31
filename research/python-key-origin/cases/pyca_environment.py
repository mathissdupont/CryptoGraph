import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def build_cipher():
    key = os.environ["CRYPTOGRAPH_TEST_KEY"].encode()
    return AESGCM(key)
