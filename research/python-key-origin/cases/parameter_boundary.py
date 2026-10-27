import os
from Crypto.Cipher import AES

def encrypt(data, key):
    return AES.new(key, AES.MODE_ECB)
