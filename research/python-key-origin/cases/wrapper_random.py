import os
from Crypto.Cipher import AES

def make_key():
    return os.urandom(16)

def encrypt(data):
    key = make_key()
    return AES.new(key, AES.MODE_ECB)
