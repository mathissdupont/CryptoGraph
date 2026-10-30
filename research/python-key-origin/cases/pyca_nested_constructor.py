import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def build_cipher():
    key = os.urandom(16)
    iv = os.urandom(16)
    return Cipher(algorithms.AES(key), modes.CBC(iv))
