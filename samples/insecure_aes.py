from Crypto.Cipher import AES


def encrypt_token(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

