"""
BASIC LEVEL: Simple symmetric encryption
Tests fundamental crypto operation detection
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def encrypt_simple_data(plaintext: str, password: str) -> bytes:
    """
    Basic symmetric encryption - should be easily detected
    """
    # Generate IV (secure)
    iv = os.urandom(16)
    
    # Create key from password (naive approach for testing)
    key = password.ljust(32)[:32].encode()
    
    # Create cipher
    cipher = Cipher(
        algorithms.AES(key.ljust(32)[:32]),
        modes.CBC(iv),
        backend=default_backend()
    )
    
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    
    return iv + ciphertext

def hash_password_simple(password: str) -> str:
    """
    Simple hash - straight detection
    """
    import hashlib
    return hashlib.sha256(password.encode()).hexdigest()

if __name__ == "__main__":
    encrypted = encrypt_simple_data("secret message", "password123")
    hashed = hash_password_simple("userpassword")
    print(f"Encrypted: {encrypted.hex()}")
    print(f"Hashed: {hashed}")
