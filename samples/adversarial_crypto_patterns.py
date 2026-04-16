"""
Adversarial-but-realistic crypto usage patterns.

These samples avoid toy direct calls where possible. They exercise alias imports,
wrapper functions, class dispatch, keyword-heavy constructors, nested helpers,
and parameters flowing through several ordinary application layers.
"""

import os
from hashlib import pbkdf2_hmac as derive_key

from Crypto.Cipher import AES as BlockCipher
from cryptography.hazmat.backends import default_backend as backend_factory
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher as CipherPipe
from cryptography.hazmat.primitives.ciphers import algorithms as algs
from cryptography.hazmat.primitives.ciphers import modes as modez


def _looks_like_business_logic(user_record: dict, field: str) -> bytes:
    selected = user_record.get(field, "")
    normalized = f"tenant:{selected}".encode("utf-8")
    return derive_key("sha256", normalized, b"pepper-and-salt", 120_000, dklen=32)


def _pycryptodome_wrapper(secret: bytes, payload: bytes, mode_name: str) -> bytes:
    mode_map = {
        "safe": BlockCipher.MODE_GCM,
        "legacy": BlockCipher.MODE_EAX,
    }
    nonce = os.urandom(12)
    cipher = BlockCipher.new(secret, mode_map.get(mode_name, BlockCipher.MODE_GCM), nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(payload)
    return nonce + tag + ciphertext


def nested_hazmat_pipeline(data: bytes, password_record: dict) -> bytes:
    material = _looks_like_business_logic(password_record, "password")

    def mode_factory(counter: bytes):
        if len(counter) == 16:
            return modez.CTR(counter)
        return modez.CBC(counter + b"\x00" * (16 - len(counter)))

    iv = os.urandom(16)
    cipher = CipherPipe(
        algorithm=algs.AES(material),
        mode=mode_factory(iv),
        backend=backend_factory(),
    )
    encryptor = cipher.encryptor()
    return encryptor.update(data[:16].ljust(16, b"\x00")) + encryptor.finalize()


class MessageSigner:
    def __init__(self, tenant_secret: bytes) -> None:
        self.tenant_secret = tenant_secret

    def _mac(self, message: bytes, digest_factory=hashes.SHA256) -> bytes:
        signer = hmac.HMAC(self.tenant_secret, digest_factory(), backend=backend_factory())
        signer.update(message)
        return signer.finalize()

    def seal(self, message: bytes, profile: dict) -> dict:
        encrypted = _pycryptodome_wrapper(
            self.tenant_secret,
            message + self._mac(message),
            profile.get("mode", "safe"),
        )
        return {"body": encrypted.hex(), "profile": profile.get("id", "unknown")}


def dispatch_from_controller(request: dict) -> dict:
    key = _looks_like_business_logic(request, "password")
    signer = MessageSigner(key)
    first = nested_hazmat_pipeline(request.get("payload", b""), request)
    second = signer.seal(first, {"mode": request.get("mode", "safe"), "id": "tenant-a"})
    return second
