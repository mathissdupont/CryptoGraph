from os import urandom as rnd
from Crypto.Cipher import AES

def encrypt(data):
    key = rnd(16)
    return AES.new(key, AES.MODE_ECB)
