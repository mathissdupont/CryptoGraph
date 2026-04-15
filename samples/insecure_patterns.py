"""
MIXED LEVEL: Insecure crypto patterns
Bad practices that should trigger multiple rules
Tests: rule matching, anti-pattern detection, combined risks
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import os
import logging

logging.basicConfig(level=logging.DEBUG)

# Pattern 1: ECB mode (insecure)
def encrypt_ecb_bad(plaintext: str, key: bytes) -> bytes:
    """ECB is insecure - leaks patterns"""
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),  # HIGH RISK
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext.encode()) + encryptor.finalize()

# Pattern 2: Hardcoded salt in PBKDF2
def kdf_with_hardcoded_salt(password: str) -> bytes:
    """Hardcoded salt defeats PBKDF2 purpose"""
    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"hardcodedsalt123",  # BAD: predictable
        iterations=10000,  # Also too low
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Pattern 3: MD5 hashing
def hash_with_md5(data: str) -> str:
    """MD5 is cryptographically broken"""
    import hashlib
    return hashlib.md5(data.encode()).hexdigest()

# Pattern 4: Deprecated SHA-1
def hash_with_sha1(data: str) -> str:
    """SHA-1 is deprecated"""
    import hashlib
    return hashlib.sha1(data.encode()).hexdigest()

# Pattern 5: Small RSA key
def generate_small_rsa_key():
    """RSA with insufficient key size"""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=512,  # INSECURE: should be 2048+
        backend=default_backend()
    )

# Pattern 6: RSA PKCS#1 v1.5 padding
def rsa_encrypt_insecure_padding(plaintext: str, public_key) -> bytes:
    """PKCS#1 v1.5 is vulnerable to padding oracle"""
    return public_key.encrypt(
        plaintext.encode(),
        padding.PKCS1v15()  # VULNERABLE
    )

# Pattern 7: Logging sensitive data
def process_with_logging(encryption_key: bytes, data: str) -> bytes:
    """Key material is logged - data exposure"""
    logging.debug(f"Processing with key: {encryption_key}")  # BAD: logging key
    
    cipher = Cipher(
        algorithms.AES(encryption_key),
        modes.GCM(os.urandom(12)),
        backend=default_backend()
    )
    
    encryptor = cipher.encryptor()
    result = encryptor.update(data.encode()) + encryptor.finalize()
    
    logging.debug(f"Encrypted result: {result.hex()}")  # Bad: logging ciphertext
    return result

# Pattern 8: Weak PRNG for cryptography
def weak_random_crypto(password: str) -> bytes:
    """Using weak random for crypto-critical purposes"""
    import random
    
    # Generate "random" key - NOT cryptographically secure
    key_parts = [random.randint(0, 255) for _ in range(32)]
    key = bytes(key_parts)
    
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(os.urandom(12)),
        backend=default_backend()
    )
    
    encryptor = cipher.encryptor()
    return encryptor.update(password.encode()) + encryptor.finalize()

# Pattern 9: IV/Nonce reuse risk
class CipherWithStaticIV:
    """Using static IV across multiple encryptions"""
    
    def __init__(self, key: bytes):
        self.key = key
        self.static_iv = os.urandom(12)  # Created once
    
    def encrypt_multiple(self, messages: list[str]) -> list[bytes]:
        """Reuses same IV - INSECURE if key is reused"""
        results = []
        for msg in messages:
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.GCM(self.static_iv),  # SAME IV EVERY TIME
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            results.append(encryptor.update(msg.encode()) + encryptor.finalize())
        return results

# Pattern 10: Insecure pickling of crypto objects
def insecure_serialization(key: bytes):
    """Using pickle with cryptographic objects"""
    import pickle
    
    key_data = {
        "key": key,
        "algorithm": "AES",
        "mode": "GCM"
    }
    
    # Pickle is insecure for cryptographic material
    return pickle.dumps(key_data)

# Pattern 11: CBC without authentication
def cbc_without_auth(plaintext: str, key: bytes) -> bytes:
    """CBC mode without authentication - vulnerable to tampering"""
    iv = os.urandom(16)
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),  # Needs HMAC elsewhere
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    
    # Just return ciphertext - no authentication tag
    return ciphertext

# Pattern 12: Key derivation with low iteration count
def weak_pbkdf2(password: str) -> bytes:
    """PBKDF2 with insufficient iterations"""
    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=os.urandom(16),
        iterations=1000,  # Should be 100000+
        backend=default_backend()
    )
    return kdf.derive(password.encode())

if __name__ == "__main__":
    key = os.urandom(32)
    
    # Test insecure patterns
    print("[ECB MODE]", encrypt_ecb_bad("test", key).hex()[:32])
    print("[MD5]", hash_with_md5("test"))
    print("[SHA-1]", hash_with_sha1("test"))
    
    # Test weak crypto
    print("[WEAK PBKDF2]", weak_pbkdf2("pass").hex()[:32])
    print("[WEAK RANDOM]", weak_random_crypto("pass").hex()[:32])
    
    # Test IV reuse
    cipher_obj = CipherWithStaticIV(key)
    results = cipher_obj.encrypt_multiple(["msg1", "msg2", "msg3"])
    print("[IV REUSE - Multiple encryptions created]")
    
    # Test insecure padding
    priv_key = generate_small_rsa_key()
    pub_key = priv_key.public_key()
    print("[SMALL RSA KEY + PKCS#1v15]")
