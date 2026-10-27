import os
from Crypto.Cipher import AES

def fake_urandom(n):
    return b"0" * n

def encrypt(data):
    key = fake_urandom(16)
    return AES.new(key, AES.MODE_ECB)
