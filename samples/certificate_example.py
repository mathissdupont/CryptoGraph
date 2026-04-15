"""X.509 certificate generation and validation examples."""

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import datetime

def generate_self_signed_cert():
    """Generate a self-signed X.509 certificate."""
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Certificate subject
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"example.com"),
    ])
    
    # Build certificate
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(u"example.com"),
            x509.DNSName(u"www.example.com"),
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256(), default_backend())
    
    return cert, private_key

def serialize_certificate(cert, private_key) -> tuple:
    """Serialize certificate and key to PEM format."""
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return cert_pem, key_pem

# Usage
if __name__ == "__main__":
    cert, private_key = generate_self_signed_cert()
    cert_pem, key_pem = serialize_certificate(cert, private_key)
    
    print(f"Certificate serial: {cert.serial_number}")
    print(f"Certificate PEM length: {len(cert_pem)} bytes")
    print(f"Private key PEM length: {len(key_pem)} bytes")
    
    # Extract certificate details
    print(f"Subject: {cert.subject.rfc4514_string()}")
    print(f"Issuer: {cert.issuer.rfc4514_string()}")
