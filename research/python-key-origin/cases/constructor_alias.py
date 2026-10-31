import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM as GCM


def build_cipher():
    return GCM(os.urandom(16))
