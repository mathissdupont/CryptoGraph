from Crypto.Cipher import AES


def build_cipher(os):
    key = os.urandom(16)
    return AES.new(key, AES.MODE_ECB)
