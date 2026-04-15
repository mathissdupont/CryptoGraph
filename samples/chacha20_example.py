"""ChaCha20 stream cipher examples."""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_stream(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
    """Encrypt data using ChaCha20 stream cipher."""
    cipher = Cipher(
        algorithms.ChaCha20(key, nonce),
        mode=None,
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def decrypt_stream(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """Decrypt ChaCha20 encrypted data."""
    cipher = Cipher(
        algorithms.ChaCha20(key, nonce),
        mode=None,
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Usage
if __name__ == "__main__":
    import os
    
    key = os.urandom(32)  # 256-bit key
    nonce = os.urandom(12)  # 96-bit nonce
    plaintext = b"Secret message to encrypt with ChaCha20"
    
    ciphertext = encrypt_stream(plaintext, key, nonce)
    recovered = decrypt_stream(ciphertext, key, nonce)
    
    print(f"Plaintext: {plaintext}")
    print(f"Recovered: {recovered}")
    print(f"Match: {plaintext == recovered}")
