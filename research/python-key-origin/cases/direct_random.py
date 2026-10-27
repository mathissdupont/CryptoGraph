import os
from Crypto.Cipher import AES

def encrypt(data):
    key = os.urandom(16)
    return AES.new(key, AES.MODE_ECB)
