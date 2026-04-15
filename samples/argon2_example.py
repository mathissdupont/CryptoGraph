"""Argon2 password hashing examples."""

from cryptography.hazmat.primitives.kdf.argon2 import Argon2
from cryptography.hazmat.backends import default_backend
import os

def hash_password_argon2(password: str) -> tuple:
    """Hash a password using Argon2."""
    salt = os.urandom(16)
    password_bytes = password.encode()
    
    kdf = Argon2(
        memory_cost=65540,
        time_cost=3,
        parallelism=4,
        length=32,
        salt=salt
    )
    key = kdf.derive(password_bytes)
    return key, salt

def verify_password_argon2(password: str, stored_hash: bytes, salt: bytes) -> bool:
    """Verify a password against an Argon2 hash."""
    password_bytes = password.encode()
    
    kdf = Argon2(
        memory_cost=65540,
        time_cost=3,
        parallelism=4,
        length=32,
        salt=salt
    )
    try:
        kdf.verify(password_bytes, stored_hash)
        return True
    except Exception:
        return False

# Usage
if __name__ == "__main__":
    password = "MySecurePassword123!"
    
    # Hash password
    password_hash, salt = hash_password_argon2(password)
    print(f"Argon2 hash length: {len(password_hash)} bytes")
    print(f"Salt length: {len(salt)} bytes")
    
    # Verify password
    is_correct = verify_password_argon2(password, password_hash, salt)
    print(f"Password verification: {is_correct}")
    
    # Test wrong password
    is_wrong = verify_password_argon2("WrongPassword", password_hash, salt)
    print(f"Wrong password verification: {is_wrong}")
