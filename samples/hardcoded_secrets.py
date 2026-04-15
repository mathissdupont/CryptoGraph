"""
INTERMEDIATE LEVEL: Hardcoded secrets detection
Tests: string literal tracking, credential detection, anti-patterns
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
import os

# Anti-pattern 1: Hardcoded key directly
HARDCODED_KEY = b"my_secret_key_1234567890abcdef"

# Anti-pattern 2: Hardcoded as string
SECRET_PASSWORD = "SuperSecurePassword123!"

# Anti-pattern 3: Hardcoded token
API_TOKEN = "sk-1234567890abcdefghijklmnopqrst"

# Anti-pattern 4: Hardcoded salt
FIXED_SALT = b"saltsaltsalt1234"

def encrypt_with_hardcoded_key(plaintext: str) -> bytes:
    """Uses global hardcoded key - bad practice"""
    iv = os.urandom(16)
    cipher = Cipher(
        algorithms.AES(HARDCODED_KEY),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    return iv + encryptor.update(plaintext.encode()) + encryptor.finalize()

def hash_with_hardcoded_password(data: str) -> str:
    """Uses hardcoded password for HMAC"""
    h = hmac.HMAC(SECRET_PASSWORD.encode(), hashes.SHA256(), backend=default_backend())
    h.update(data.encode())
    return h.finalize().hex()

def derive_with_hardcoded_salt(password: str) -> bytes:
    """Key derivation with fixed salt - should always be random"""
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=FIXED_SALT,  # BAD: hardcoded salt
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Anti-pattern 5: Hardcoded in function
def get_database_credentials():
    """Credentials as hardcoded strings"""
    return {
        "db_host": "prod.example.com",
        "db_user": "admin",
        "db_password": "Admin@123456",
        "api_key": "AK-ZXc9JK3nFqP2vL8mN5oR6sT7uV"
    }

# Anti-pattern 6: Credentials in config dict
CONFIG = {
    "encryption_key": "prod_key_abc123def456",
    "backup_password": "2ndaryK3y!@#$%",
    "oauth_secret": "secret_oauth_token_for_prod",
    "signing_key": bytes.fromhex("48656c6c6f576f726c6431323334")
}

def process_with_hardcoded_config(data: str) -> str:
    """Uses hardcoded config - keys exposed in code"""
    # Use key from config
    key = CONFIG["encryption_key"].encode()[:32]
    
    # This is bad: key material directly in code
    cipher = Cipher(
        algorithms.AES(key.ljust(32)[:32]),
        modes.ECB(),  # Also bad: ECB mode
        backend=default_backend()
    )
    
    encryptor = cipher.encryptor()
    return encryptor.update(data.encode()).hex()

# Anti-pattern 7: Key in environment variable (name hardcoded but value not)
import os as _os
ENV_KEY = _os.environ.get("SECRET_KEY", b"fallback_hardcoded_key_ABC123")

# Anti-pattern 8: Private key material
PRIVATE_KEY_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2a2rwplBCqwRjF7D3vVz7VV4x1Z1c5x7L4vE3P8J8vL1K7X3
VQ2K3F8X1P9L7M3K9X4Q2R8Y1P9M7N4L9X5R3S9Z2Q0N8O5M0Y6S4T0A3R1P9M7
N4L0Y6S4T0A3R1P9M7N4L0Y6S4T0A3R1P9M7N4L0Y6S4T0A3R1P9M7N4L0AAAABIjALBgkqhkiG9w0BAQsFAAOCAQEAwF5K
-----END RSA PRIVATE KEY-----"""

def use_hardcoded_private_key():
    """Loading private key from hardcoded PEM - data exposure risk"""
    from cryptography.hazmat.primitives import serialization
    private_key = serialization.load_pem_private_key(
        PRIVATE_KEY_PEM.encode(),
        password=None,
        backend=default_backend()
    )
    return private_key

if __name__ == "__main__":
    # Test various hardcoded anti-patterns
    encrypted1 = encrypt_with_hardcoded_key("test data")
    print(f"Encrypted with hardcoded key: {encrypted1.hex()[:32]}...")
    
    hashed = hash_with_hardcoded_password("data")
    print(f"HMAC with hardcoded password: {hashed[:32]}...")
    
    derived = derive_with_hardcoded_salt("password")
    print(f"Key derived with hardcoded salt: {derived.hex()[:32]}...")
    
    creds = get_database_credentials()
    print(f"Credentials: {list(creds.keys())}")
    
    result = process_with_hardcoded_config("secret message")
    print(f"Processed with hardcoded config: {result[:32]}...")
