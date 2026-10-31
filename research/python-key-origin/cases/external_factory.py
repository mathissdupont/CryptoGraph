from application_keys import fetch_key
from Crypto.Cipher import AES


def build_cipher():
    key = fetch_key()
    return AES.new(key, AES.MODE_ECB)
