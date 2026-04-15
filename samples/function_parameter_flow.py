"""
ADVANCED LEVEL: Function parameter flow
Key material passed through function parameters
Tests: parameter tracking, call-site analysis, inter-procedural DFG
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
import os

def base_encrypt(plaintext: str, key: bytes, iv: bytes, mode_obj) -> bytes:
    """
    Low-level encrypt function - accepts key as parameter
    Tests: parameter DFG tracking
    """
    cipher = Cipher(
        algorithms.AES(key),
        mode_obj,
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext.encode()) + encryptor.finalize()

def encrypt_with_mode_factory(plaintext: str, key: bytes, mode_type: str = "gcm") -> bytes:
    """
    Factory function - creates mode then passes to encrypt
    Tests: indirect parameter flow
    """
    iv = os.urandom(16 if mode_type == "cbc" else 12)
    
    if mode_type == "gcm":
        mode = modes.GCM(iv)
    else:
        mode = modes.CBC(iv)
    
    # Pass both key and mode to low-level function
    return base_encrypt(plaintext, key, iv, mode)

def nested_encrypt(plaintext: str, password: str, level: int = 1) -> bytes:
    """
    Recursive/nested encryption - tests nested parameter flow
    """
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    
    # Derive key from password
    salt = os.urandom(16)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    
    # Encrypt at current level
    iv = os.urandom(12)
    mode = modes.GCM(iv)
    ciphertext = base_encrypt(plaintext, key, iv, mode)
    
    # Recursive re-encryption if level > 1
    if level > 1:
        next_password = f"{password}_level_{level}"
        return nested_encrypt(ciphertext.hex(), next_password, level - 1)
    
    return ciphertext

def key_transformation_chain(original_key: bytes, *transformations: str) -> bytes:
    """
    Apply series of transformations to key parameter
    Tests: key parameter modifications across call chain
    """
    key = original_key
    
    for transform in transformations:
        if transform == "hash":
            h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
            h.update(b"transform")
            key = h.finalize()
        elif transform == "double":
            key = key + key
        elif transform == "compress":
            key = key[:len(key)//2]
    
    return key[:32]  # Normalize to 32 bytes

def encrypt_with_transformed_key(plaintext: str, base_key: bytes, *transforms: str) -> bytes:
    """
    Uses parametrized transformation chain
    Tests: complex parameter transformation flow
    """
    transformed_key = key_transformation_chain(base_key, *transforms)
    iv = os.urandom(12)
    mode = modes.GCM(iv)
    return base_encrypt(plaintext, transformed_key, iv, mode)

def multi_recipient_encrypt(plaintext: str, recipients: list[tuple[str, bytes]]) -> dict:
    """
    Encrypt same data with different recipient keys
    Tests: loop-based parameter flow analysis
    """
    results = {}
    
    for recipient_name, recipient_key in recipients:
        iv = os.urandom(12)
        mode = modes.GCM(iv)
        ciphertext = base_encrypt(plaintext, recipient_key, iv, mode)
        results[recipient_name] = {
            "ciphertext": ciphertext.hex(),
            "iv": iv.hex()
        }
    
    return results

class CryptoEngine:
    """
    Object with methods receiving key parameters
    Tests: object method parameter tracking
    """
    
    def __init__(self, algorithm_config: dict):
        self.config = algorithm_config
    
    def process_key(self, key: bytes, operation: str = "encrypt") -> bytes:
        """Process key via object method"""
        if operation == "hash":
            h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
            h.update(b"process")
            return h.finalize()
        elif operation == "truncate":
            return key[:16]
        return key
    
    def encrypt_data(self, plaintext: str, key: bytes, processed: bool = False) -> bytes:
        """Encrypt with optional key processing"""
        if processed:
            # Key passed through method
            final_key = self.process_key(key, "encrypt")
        else:
            final_key = key
        
        iv = os.urandom(12)
        mode = modes.GCM(iv)
        return base_encrypt(plaintext, final_key, iv, mode)

if __name__ == "__main__":
    # Test 1: Basic parameter flow
    key = os.urandom(32)
    result1 = encrypt_with_mode_factory("test data", key, "gcm")
    print(f"Mode factory: {result1.hex()[:32]}...")
    
    # Test 2: Nested encryption
    result2 = nested_encrypt("nested secret", "password", 2)
    print(f"Nested encryption: {result2.hex()[:32]}...")
    
    # Test 3: Key transformation
    result3 = encrypt_with_transformed_key("transformed", key, "hash", "double", "compress")
    print(f"Transformed key: {result3.hex()[:32]}...")
    
    # Test 4: Multi-recipient
    recipients = [
        ("alice", os.urandom(32)),
        ("bob", os.urandom(32))
    ]
    result4 = multi_recipient_encrypt("broadcast", recipients)
    print(f"Multi-recipient: {list(result4.keys())}")
    
    # Test 5: Object method flow
    engine = CryptoEngine({"algo": "AES", "mode": "GCM"})
    result5 = engine.encrypt_data("object data", key, processed=True)
    print(f"Object method: {result5.hex()[:32]}...")
