"""ECDSA digital signature examples."""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

def generate_ecdsa_keypair() -> tuple:
    """Generate ECDSA key pair."""
    private_key = ec.generate_private_key(
        ec.SECP256R1(),
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message_ecdsa(message: bytes, private_key) -> bytes:
    """Sign a message using ECDSA."""
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def verify_signature_ecdsa(message: bytes, signature: bytes, public_key) -> bool:
    """Verify ECDSA signature."""
    try:
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception:
        return False

# Usage
if __name__ == "__main__":
    # Generate key pair
    private_key, public_key = generate_ecdsa_keypair()
    
    # Sign message
    message = b"Document to sign with ECDSA"
    signature = sign_message_ecdsa(message, private_key)
    
    # Verify signature
    is_valid = verify_signature_ecdsa(message, signature, public_key)
    print(f"ECDSA signature valid: {is_valid}")
    
    # Serialize keys
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    print(f"Private key length: {len(private_pem)} bytes")
