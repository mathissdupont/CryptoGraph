from Crypto.Cipher import AES


def read_login_request(request):
    return request["token"], request["key"]


def encrypt_auth_token(token, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(token)


def login(request):
    token, key = read_login_request(request)
    return encrypt_auth_token(token, key)
