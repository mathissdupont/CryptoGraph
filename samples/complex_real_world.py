"""
ADVANCED LEVEL: Complex real-world patterns
Mimics realistic encryption scenarios with hidden vulnerabilities
Tests: complex DFG, realistic code patterns, vulnerability combinations
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os
import json
from typing import Optional

class ManagedEncryptionService:
    """
    Realistic service-like class managing encryption
    Hides vulnerabilities in realistic code patterns
    """
    
    def __init__(self, master_password: str):
        self.master_password = master_password
        self.key_cache = {}
        self.configuration = {
            "algorithm": "AES",
            "key_size": 256,
            "mode": "GCM",
            "hmac_enabled": True
        }
    
    def _derive_session_key(self, user_id: int, session_token: str) -> bytes:
        """
        Multi-step key derivation with multiple parameters
        Tests: complex variable flow
        """
        # Create combined input
        combined_input = f"{user_id}:{session_token}:{self.master_password}"
        
        # First KDF pass
        first_pass = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"fixed_salt",  # VULNERABILITY: hardcoded salt
            iterations=50000,  # Should be 100000+
            backend=default_backend()
        ).derive(combined_input.encode())
        
        # Second KDF pass (info derivation)
        second_pass = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=first_pass,
            info=b"session_key",
            backend=default_backend()
        ).derive(first_pass)
        
        return second_pass[:32]
    
    def cache_key(self, key_id: str, user_id: int, session: str):
        """
        Cache derived key - vulnerability: in-memory caching
        Tests: data structure tracking
        """
        key = self._derive_session_key(user_id, session)
        self.key_cache[key_id] = {
            "key": key,
            "user_id": user_id,
            "session": session,
            "cached_at": os.urandom(4).hex()
        }
        return key
    
    def encrypt_sensitive_document(
        self, 
        document: dict, 
        encryption_key: bytes,
        metadata: Optional[dict] = None
    ) -> str:
        """
        Complicated encryption with metadata
        Tests: complex parameter combinations
        """
        # Serialize document
        doc_json = json.dumps(document)
        
        # Create IV
        iv = os.urandom(12)
        
        # Prepare cipher
        cipher = Cipher(
            algorithms.AES(encryption_key[:32]),
            modes.GCM(iv),
            backend=default_backend()
        )
        
        encryptor = cipher.encryptor()
        
        # Add metadata as additional authenticated data
        if metadata:
            encryptor.authenticate_additional_data(json.dumps(metadata).encode())
        
        ciphertext = encryptor.update(doc_json.encode()) + encryptor.finalize()
        
        # Return combined encrypted blob
        result = {
            "ciphertext": ciphertext.hex(),
            "iv": iv.hex(),
            "tag": encryptor.tag.hex() if hasattr(encryptor, 'tag') else "",
            "algorithm": self.configuration["algorithm"],
            "mode": self.configuration["mode"]
        }
        
        return json.dumps(result)
    
    def process_batch_encryption(
        self, 
        documents: list[dict], 
        user_id: int,
        encryption_params: dict
    ) -> list[str]:
        """
        Batch processing - multiple crypto operations in loop
        Tests: loop-based data flow
        """
        results = []
        
        for idx, doc in enumerate(documents):
            # Derive per-document key (each with same user_id - VULNERABILITY)
            doc_key = self._derive_session_key(user_id, f"doc_{idx}")
            
            # Encrypt document
            encrypted = self.encrypt_sensitive_document(
                doc,
                doc_key,
                metadata={"doc_index": idx, "user_id": user_id}
            )
            
            results.append(encrypted)
        
        return results

class DatabaseBackedCrypto:
    """
    Crypto tied to database operations
    Tests: inter-module data flow (would span files)
    """
    
    def __init__(self, db_connection_string: str):
        self.db_string = db_connection_string
        self.local_key = os.urandom(32)
    
    def retrieve_and_decrypt(self, record_id: int) -> Optional[str]:
        """
        Simulated: retrieve encrypted record from DB and decrypt
        Tests: external data source tracking
        """
        # In reality, would query DB
        # db_result = database.query(f"SELECT encrypted_data FROM records WHERE id = {record_id}")
        
        # For testing, use hardcoded
        if record_id == 1:
            encrypted_hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
            iv_hex = "000102030405060708090a0b0c"
            
            # Derive decryption key via stored password
            password = "db_password"  # VULNERABILITY: hardcoded
            
            kdf = PBKDF2(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b"from_metadata",  # In reality from DB
                iterations=100000,
                backend=default_backend()
            )
            derived_key = kdf.derive(password.encode())
            
            # Decrypt
            cipher = Cipher(
                algorithms.AES(derived_key),
                modes.GCM(bytes.fromhex(iv_hex)),
                backend=default_backend()
            )
            
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(bytes.fromhex(encrypted_hex)) + decryptor.finalize()
            
            return plaintext.decode()
        
        return None

def complex_crypto_flow(
    user_credentials: dict,
    data_to_protect: str,
    encryption_level: int
) -> dict:
    """
    High-level flow combining multiple crypto operations
    Tests: complete DFG from input to crypto operations
    """
    # Extract credentials
    username = user_credentials.get("username", "")
    password = user_credentials.get("password", "")
    api_key = user_credentials.get("api_key", "")
    
    # Multi-parameter key derivation
    combined_secret = f"{username}:{password}:{api_key}"
    
    # Choose algorithm based on level
    if encryption_level >= 3:
        # High security: multi-pass KDF
        salt = os.urandom(16)
        kdf1 = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key_pass1 = kdf1.derive(combined_secret.encode())
        
        kdf2 = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=key_pass1,
            info=b"high_security",
            backend=default_backend()
        )
        final_key = kdf2.derive(key_pass1)
    else:
        # Medium/low: simple derivation
        final_key = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"simple_salt",  # VULNERABILITY
            iterations=10000,  # VULNERABILITY
            backend=default_backend()
        ).derive(combined_secret.encode())
    
    # Encrypt data
    iv = os.urandom(12)
    cipher = Cipher(
        algorithms.AES(final_key[:32]),
        modes.GCM(iv),
        backend=default_backend()
    )
    
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data_to_protect.encode()) + encryptor.finalize()
    
    return {
        "encrypted": ciphertext.hex(),
        "iv": iv.hex(),
        "level": encryption_level,
        "user": username
    }

if __name__ == "__main__":
    # Test service
    service = ManagedEncryptionService("master_secret_password")
    
    # Cache some keys
    key = service.cache_key("user_123_session", 123, "session_token_abc")
    print(f"[ManagedService] Key cached")
    
    # Encrypt batch
    docs = [
        {"id": 1, "content": "document 1"},
        {"id": 2, "content": "document 2"}
    ]
    encrypted = service.process_batch_encryption(docs, 123, {})
    print(f"[ManagedService] Encrypted {len(encrypted)} documents")
    
    # Test complex flow
    creds = {
        "username": "alice",
        "password": "secret_password",
        "api_key": "sk_test_123456"
    }
    result = complex_crypto_flow(creds, "very sensitive data", encryption_level=2)
    print(f"[ComplexFlow] Encryption result: {result['encrypted'][:32]}...")
    
    # Test database backed
    db_crypto = DatabaseBackedCrypto("postgres://user:pass@localhost/db")
    decrypted = db_crypto.retrieve_and_decrypt(1)
    print(f"[DatabaseBacked] Operation completed")
