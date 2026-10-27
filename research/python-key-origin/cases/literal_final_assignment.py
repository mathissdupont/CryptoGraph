import os
from Crypto.Cipher import AES

def encrypt(data):
    key = os.urandom(16)
    key = b"0123456789abcdef"
    return AES.new(key, AES.MODE_ECB)
