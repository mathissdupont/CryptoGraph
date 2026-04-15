"""
INTERMEDIATE LEVEL: Control flow variants
Different encryption methods used based on conditions
Tests: control flow analysis, conditional crypto operations
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2
import os

def encrypt_with_mode(plaintext: str, key: bytes, mode_type: str = "gcm") -> bytes:
    """
    Different modes based on parameter - tests control flow
    """
    iv = os.urandom(16)
    
    if mode_type == "gcm":
        mode = modes.GCM(iv)
    elif mode_type == "cbc":
        mode = modes.CBC(iv)
    elif mode_type == "ctr":
        mode = modes.CTR(iv)
    else:
        mode = modes.ECB()  # INSECURE - intentional for detection
    
    cipher = Cipher(
        algorithms.AES(key),
        mode,
        backend=default_backend()
    )
    
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext.encode()) + encryptor.finalize()

def derive_key_conditionally(password: str, algorithm: str = "argon2") -> bytes:
    """
    Different KDF based on algorithm parameter
    Tests control flow in key derivation
    """
    salt = os.urandom(16)
    
    if algorithm == "argon2":
        kdf = Argon2(
            time_cost=2,
            memory_cost=65536,
            parallelism=4,
            hash_algorithm=hashes.SHA256(),
            salt=salt
        )
    elif algorithm == "pbkdf2":
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")
    
    return kdf.derive(password.encode())

def conditional_security_level(data: str, security_level: int) -> bytes:
    """
    Different security parameters based on level
    Tests conditional crypto configuration
    """
    if security_level >= 3:
        # High security: AES-256 + Argon2 + GCM
        key = derive_key_conditionally("secure_password", "argon2")[:32]
        return encrypt_with_mode(data, key, "gcm")
    elif security_level == 2:
        # Medium: AES-128 + PBKDF2 + CBC
        key = derive_key_conditionally("medium_password", "pbkdf2")[:16]
        return encrypt_with_mode(data, key, "cbc")
    else:
        # Low (bad practice): No encryption or ECB
        key = b"fixedkey1234567890123456"
        return encrypt_with_mode(data, key.ljust(32)[:32], "ecb")

if __name__ == "__main__":
    # Test different paths
    result_high = conditional_security_level("high security data", 3)
    result_medium = conditional_security_level("medium security data", 2)
    result_low = conditional_security_level("low security data", 1)  # Intentional weakness
    
    print(f"High security: {result_high.hex()[:32]}...")
    print(f"Medium security: {result_medium.hex()[:32]}...")
    print(f"Low security: {result_low.hex()[:32]}...")
