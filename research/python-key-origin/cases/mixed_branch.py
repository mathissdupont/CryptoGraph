import os
from Crypto.Cipher import AES

def encrypt(data, use_random):
    if use_random:
        key = os.urandom(16)
    else:
        key = b"0123456789abcdef"
    return AES.new(key, AES.MODE_ECB)
