"""
ADVANCED LEVEL: Obfuscated key material
Key material in data structures, indirect access patterns
Tests: alias analysis, data structure tracking, complex control flow
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
import os

class CryptoProtocol:
    """Container for crypto operations - tests object property tracking"""
    
    def __init__(self):
        self.keys = {}
        self.config = {
            "cipher": algorithms.AES,
            "mode": modes.GCM,
            "hash_algo": hashes.SHA256
        }
    
    def register_key(self, name: str, key_material: bytes):
        """Store key in dict - tests alias analysis"""
        self.keys[name] = key_material
    
    def get_key(self, name: str) -> bytes:
        """Retrieve key from dict"""
        return self.keys.get(name, b"")
    
    def encrypt_with_registered_key(self, key_name: str, plaintext: str) -> bytes:
        """Encrypt using registered key - requires dict tracking"""
        key = self.get_key(key_name)
        iv = os.urandom(16)
        
        cipher = Cipher(
            self.config["cipher"](key),
            self.config["mode"](iv),
            backend=default_backend()
        )
        
        encryptor = cipher.encryptor()
        return iv + encryptor.update(plaintext.encode()) + encryptor.finalize()

def complex_key_derivation(password: str, user_id: int) -> bytes:
    """
    Indirect key derivation with multiple intermediates
    Tests variable aliasing and control dependencies
    """
    # Step 1: Create base material
    base = password.encode()
    
    # Step 2: Mix with user ID
    mixed = base + str(user_id).encode()
    
    # Step 3: Hash multiple times
    h = hmac.HMAC(mixed, hashes.SHA256(), backend=default_backend())
    h.update(b"salt1")
    digest1 = h.finalize()
    
    h2 = hmac.HMAC(digest1, hashes.SHA256(), backend=default_backend())
    h2.update(b"salt2")
    digest2 = h2.finalize()
    
    # Step 4: Return derived key
    return digest2[:32]

def process_with_indirect_crypto(user_id: int, secret: str) -> dict:
    """
    Complex indirect crypto: user_id → key derivation → registration → usage
    Tests inter-procedural data flow across objects and functions
    """
    # Initialize protocol
    protocol = CryptoProtocol()
    
    # Derive key indirectly
    derived_key = complex_key_derivation(secret, user_id)
    
    # Register under computed name
    key_name = f"user_{user_id}_key"
    protocol.register_key(key_name, derived_key)
    
    # Encrypt using registered key
    message = f"User {user_id} encrypted with indirect key"
    ciphertext = protocol.encrypt_with_registered_key(key_name, message)
    
    return {
        "user_id": user_id,
        "ciphertext": ciphertext.hex(),
        "key_name": key_name
    }

# Obfuscated API access patterns
def crypto_op_via_dict_dispatch(op_type: str, data: str, key: bytes):
    """
    Dispatch based on dict lookup - tests indirect function call tracking
    """
    operations = {
        "aes_gcm": lambda d, k: Cipher(
            algorithms.AES(k[:32]), 
            modes.GCM(os.urandom(12)), 
            backend=default_backend()
        ).encryptor().update(d.encode()),
        
        "aes_cbc": lambda d, k: Cipher(
            algorithms.AES(k[:32]), 
            modes.CBC(os.urandom(16)), 
            backend=default_backend()
        ).encryptor().update(d.encode()),
    }
    
    return operations.get(op_type, lambda d, k: b"")(data, key)

if __name__ == "__main__":
    # Test complex flow
    result = process_with_indirect_crypto(12345, "my_secret_password")
    print(f"Encrypted via object: {result}")
    
    # Test indirect dispatch
    key = complex_key_derivation("test", 1)
    cipher_result = crypto_op_via_dict_dispatch("aes_gcm", "sensitive", key)
    print(f"Encrypted via dispatch: {cipher_result.hex()[:32]}...")
