from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


def encrypt_for_recipient(message):
    key = RSA.generate(2048)
    cipher = PKCS1_OAEP.new(key.publickey())
    return cipher.encrypt(message)

