"""
INTERMEDIATE LEVEL: Data flow chain
Key material flows through multiple steps to crypto operation
Tests: variable assignments, function parameters, data flow tracking
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import os

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Key derivation chain - DFG should track password → key"""
    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

def encrypt_with_derived_key(password: str, plaintext: str) -> bytes:
    """
    Tests: 
    - Variable assignment chain (password → salt → key → cipher)
    - Intermediate function calls
    """
    # Step 1: Generate salt
    salt = os.urandom(16)
    
    # Step 2: Derive key via function call (requires inter-procedural DFG)
    key = derive_key_from_password(password, salt)
    
    # Step 3: Generate IV
    iv = os.urandom(16)
    
    # Step 4: Create cipher with derived key
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    )
    
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    
    return salt + iv + ciphertext + encryptor.tag

def process_user_data(user_input: str, master_password: str) -> dict:
    """
    Multi-step crypto: user_input → processing → encryption
    Tests data provenance tracking
    """
    # Process input
    processed = user_input.strip().lower()
    
    # Add prefix
    prefixed = f"user_data:{processed}"
    
    # Encrypt
    encrypted = encrypt_with_derived_key(master_password, prefixed)
    
    return {
        "ciphertext": encrypted.hex(),
        "method": "AES-GCM-PBKDF2"
    }

if __name__ == "__main__":
    result = process_user_data("sensitive input", "master_secret")
    print(f"Encrypted: {result}")
