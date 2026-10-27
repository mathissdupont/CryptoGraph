from Crypto.Cipher import AES


def build_cipher(options):
    return AES.new(**options)
