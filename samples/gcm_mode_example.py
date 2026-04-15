"""AES GCM (Authenticated Encryption) examples."""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def encrypt_with_gcm(plaintext: bytes, key: bytes, associated_data: bytes = None) -> tuple:
    """Encrypt data with AES-GCM for authenticated encryption."""
    iv = os.urandom(12)  # 96-bit IV for GCM
    
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    if associated_data:
        encryptor.authenticate_additional_data(associated_data)
    
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    
    return ciphertext, iv, tag

def decrypt_with_gcm(ciphertext: bytes, key: bytes, iv: bytes, tag: bytes, associated_data: bytes = None) -> bytes:
    """Decrypt AES-GCM encrypted data with authentication verification."""
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    if associated_data:
        decryptor.authenticate_additional_data(associated_data)
    
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

# Usage
if __name__ == "__main__":
    key = os.urandom(32)  # 256-bit key
    plaintext = b"Sensitive data that needs authentication"
    aad = b"Version: 1.0"
    
    # Encrypt
    ciphertext, iv, tag = encrypt_with_gcm(plaintext, key, aad)
    print(f"Ciphertext length: {len(ciphertext)} bytes")
    print(f"Authentication tag: {tag.hex()}")
    
    # Decrypt
    recovered = decrypt_with_gcm(ciphertext, key, iv, tag, aad)
    print(f"Decrypted: {recovered}")
    print(f"Match: {plaintext == recovered}")
