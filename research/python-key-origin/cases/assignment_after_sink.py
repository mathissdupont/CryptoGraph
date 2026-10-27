import os
from Crypto.Cipher import AES

def encrypt(data):
    key = b"0123456789abcdef"
    cipher = AES.new(key, AES.MODE_ECB)
    key = os.urandom(16)
    return cipher
