"""
MEGA SAMPLE: Realistic crypto-heavy application in a single file.

This file intentionally mixes clear, indirect, safe, legacy, wrapper-based,
class-based, and dispatch-based cryptographic usage. It is meant to stress
CryptoGraph's extraction, call-chain, context, flow, inference, and risk views.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as std_hmac
import json
import os
import random
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterable

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


APP_PEPPER = b"demo-pepper-not-a-real-secret"
LEGACY_STATIC_IV = b"0000000000000000"
LEGACY_HARDCODED_KEY = b"0123456789abcdef"


def _json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _pad16(data: bytes) -> bytes:
    missing = 16 - (len(data) % 16)
    return data + bytes([missing]) * missing


def _unpad16(data: bytes) -> bytes:
    if not data:
        return data
    return data[: -data[-1]]


def insecure_tracking_id() -> str:
    """Bad sample: non-crypto PRNG used for an identifier that looks security-related."""
    left = random.randint(10_000, 99_999)
    right = int(random.random() * 1_000_000)
    return f"trk-{left}-{right}"


def secure_request_id(prefix: str = "req") -> str:
    token = secrets.token_urlsafe(24)
    return f"{prefix}-{token}"


def derive_login_key_pbkdf2(password: str, tenant: str, iterations: int = 180_000) -> bytes:
    salt = hashlib.sha256(f"{tenant}:login".encode("utf-8")).digest()[:16]
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)


def derive_storage_key_scrypt(passphrase: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    real_salt = salt or os.urandom(16)
    kdf = Scrypt(salt=real_salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
    return kdf.derive(passphrase.encode("utf-8")), real_salt


def derive_session_subkey(root_key: bytes, user_id: str) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=user_id.encode("utf-8"),
        info=b"session-subkey",
        backend=default_backend(),
    )
    return hkdf.derive(root_key)


def hash_password_record(password: str, tenant: str) -> dict:
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=210_000,
        backend=default_backend(),
    )
    digest = kdf.derive(f"{tenant}:{password}".encode("utf-8"))
    return {"salt": _b64(salt), "digest": _b64(digest), "kdf": "PBKDF2HMAC"}


def legacy_hash_for_migration(value: str) -> str:
    """Bad sample: intentionally obsolete hashes for migration scanning."""
    md5_part = hashlib.md5(value.encode("utf-8")).hexdigest()
    sha1_part = hashlib.sha1(value.encode("utf-8")).hexdigest()
    return f"{md5_part}:{sha1_part}"


def sign_event_stdlib(secret: bytes, event: dict) -> str:
    mac = std_hmac.new(secret, _json_bytes(event), hashlib.sha256)
    return mac.hexdigest()


def sign_event_hazmat(secret: bytes, event: dict) -> bytes:
    signer = hmac.HMAC(secret, hashes.SHA256(), backend=default_backend())
    signer.update(_json_bytes(event))
    return signer.finalize()


def verify_event(secret: bytes, event: dict, supplied_hex: str) -> bool:
    expected = sign_event_stdlib(secret, event)
    return std_hmac.compare_digest(expected, supplied_hex)


def encrypt_profile_gcm(profile: dict, key: bytes) -> dict:
    nonce = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend(),
    ).encryptor()
    ciphertext = encryptor.update(_json_bytes(profile)) + encryptor.finalize()
    return {"nonce": _b64(nonce), "tag": _b64(encryptor.tag), "ciphertext": _b64(ciphertext)}


def decrypt_profile_gcm(blob: dict, key: bytes) -> dict:
    nonce = base64.urlsafe_b64decode(blob["nonce"] + "==")
    tag = base64.urlsafe_b64decode(blob["tag"] + "==")
    ciphertext = base64.urlsafe_b64decode(blob["ciphertext"] + "==")
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),
        backend=default_backend(),
    ).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return json.loads(plaintext.decode("utf-8"))


def legacy_encrypt_export(data: bytes) -> bytes:
    """Bad sample: hardcoded key, static IV, CBC wrapper."""
    cipher = AES.new(LEGACY_HARDCODED_KEY, AES.MODE_CBC, iv=LEGACY_STATIC_IV)
    return cipher.encrypt(_pad16(data))


def legacy_ecb_blob(data: bytes) -> bytes:
    """Very bad sample: ECB mode."""
    cipher = AES.new(LEGACY_HARDCODED_KEY, AES.MODE_ECB)
    return cipher.encrypt(_pad16(data))


def pycryptodome_aead_envelope(key: bytes, data: bytes, aad: bytes) -> dict:
    cipher = AES.new(key, AES.MODE_GCM, nonce=os.urandom(12))
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return {"nonce": _b64(cipher.nonce), "tag": _b64(tag), "ciphertext": _b64(ciphertext)}


def fernet_wrap_payload(payload: dict, key: bytes | None = None) -> tuple[bytes, bytes]:
    fernet_key = key or Fernet.generate_key()
    token = Fernet(fernet_key).encrypt(_json_bytes(payload))
    return fernet_key, token


def generate_rsa_identity() -> tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def rsa_oaep_roundtrip(message: bytes) -> bytes:
    key = RSA.generate(2048)
    cipher = PKCS1_OAEP.new(key.publickey())
    ciphertext = cipher.encrypt(message)
    decipher = PKCS1_OAEP.new(key)
    return decipher.decrypt(ciphertext)


def rsa_sign_document(private_key, document: bytes) -> bytes:
    digest = hashlib.sha256(document).digest()
    return private_key.sign(
        digest,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


@dataclass
class TenantKeys:
    tenant_id: str
    root_key: bytes
    signing_key: bytes
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def session_key(self, user_id: str) -> bytes:
        return derive_session_subkey(self.root_key, f"{self.tenant_id}:{user_id}")

    def expires_at(self) -> datetime:
        return self.created_at + timedelta(hours=12)


class AuditCryptoService:
    def __init__(self, keys: TenantKeys) -> None:
        self.keys = keys
        self.handlers: dict[str, Callable[[dict], dict]] = {
            "profile": self.encrypt_profile_event,
            "legacy-export": self.encrypt_legacy_export,
            "token": self.issue_signed_token,
        }

    def encrypt_profile_event(self, event: dict) -> dict:
        user_id = event.get("user", "anonymous")
        key = self.keys.session_key(user_id)
        protected = encrypt_profile_gcm(event, key)
        protected["request_id"] = secure_request_id("profile")
        return protected

    def encrypt_legacy_export(self, event: dict) -> dict:
        plaintext = _json_bytes(event)
        return {
            "tracking": insecure_tracking_id(),
            "cbc": _b64(legacy_encrypt_export(plaintext)),
            "ecb": _b64(legacy_ecb_blob(plaintext)),
        }

    def issue_signed_token(self, event: dict) -> dict:
        body = {
            "sub": event.get("user"),
            "scope": event.get("scope", "read"),
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "rid": secure_request_id("tok"),
        }
        signature = sign_event_stdlib(self.keys.signing_key, body)
        return {"body": body, "signature": signature}

    def process(self, event: dict) -> dict:
        handler_name = event.get("type", "profile")
        handler = self.handlers.get(handler_name, self.encrypt_profile_event)
        result = handler(event)
        result["audit_mac"] = _b64(sign_event_hazmat(self.keys.signing_key, result))
        return result


def batch_process_events(service: AuditCryptoService, events: Iterable[dict]) -> list[dict]:
    results = []
    for event in events:
        if event.get("disabled"):
            continue
        results.append(service.process(event))
    return results


def bootstrap_tenant(tenant_id: str, admin_password: str) -> TenantKeys:
    root_key = derive_login_key_pbkdf2(admin_password, tenant_id)
    signing_key, _salt = derive_storage_key_scrypt(f"{tenant_id}:{admin_password}")
    return TenantKeys(tenant_id=tenant_id, root_key=root_key, signing_key=signing_key)


def application_entrypoint(requests: list[dict]) -> dict:
    tenant_id = requests[0].get("tenant", "tenant-a") if requests else "tenant-a"
    admin_password = requests[0].get("admin_password", "change-me") if requests else "change-me"
    keys = bootstrap_tenant(tenant_id, admin_password)
    service = AuditCryptoService(keys)
    results = batch_process_events(service, requests)
    return {
        "tenant": tenant_id,
        "expires_at": keys.expires_at().isoformat(),
        "results": results,
        "migration_hash": legacy_hash_for_migration(tenant_id),
    }


if __name__ == "__main__":
    demo_requests = [
        {"type": "profile", "tenant": "demo", "admin_password": "local-only", "user": "alice", "email": "a@example.test"},
        {"type": "legacy-export", "user": "bob", "payload": "archive-me"},
        {"type": "token", "user": "carol", "scope": "admin"},
    ]
    output = application_entrypoint(demo_requests)
    print(json.dumps(output, indent=2)[:500])
