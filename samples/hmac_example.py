"""HMAC message authentication examples."""

import hmac
import hashlib

def verify_signature(message: bytes, signature: bytes, secret_key: bytes) -> bool:
    """Verify HMAC-SHA256 signature."""
    expected = hmac.new(secret_key, message, hashlib.sha256).digest()
    return hmac.compare_digest(signature, expected)

def create_auth_token(user_id: str, secret: str) -> str:
    """Create authenticated token using HMAC."""
    token_data = f"user:{user_id}".encode()
    secret_bytes = secret.encode()
    token = hmac.new(secret_bytes, token_data, hashlib.sha256).hexdigest()
    return token

# Usage
if __name__ == "__main__":
    secret_key = b"super-secret-key-12345"
    message = b"important message"
    
    # Create HMAC
    mac = hmac.new(secret_key, message, hashlib.sha256)
    signature = mac.digest()
    
    # Verify
    is_valid = verify_signature(message, signature, secret_key)
    print(f"Signature valid: {is_valid}")
    
    # Auth token
    token = create_auth_token("user123", "secret-key")
    print(f"Token: {token}")
