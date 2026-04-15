"""Normalize crypto API wrappers into research-grade semantic fields."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from cryptograph.models import CryptoFinding

UNKNOWN = "unknown"


@dataclass(frozen=True)
class NormalizedCrypto:
    algorithm: str
    primitive: str
    provider: str | None
    mode: str | None
    padding: str | None
    key_size: int | str | None
    operation: str
    evidence: list[str]


def normalize_finding(finding: CryptoFinding) -> NormalizedCrypto:
    """Return semantic crypto metadata independent from wrapper API shape."""
    args = [str(arg) for arg in finding.arguments]
    arg_text = " ".join(args)
    api = finding.api_name
    algorithm = finding.algorithm
    primitive = finding.primitive
    provider = finding.provider
    evidence: list[str] = []

    if api == "Cipher":
        inner_algorithm = _inner_cipher_algorithm(arg_text)
        if inner_algorithm:
            algorithm = inner_algorithm
            evidence.append(f"Resolved inner Cipher algorithm from arguments: {inner_algorithm}")
        mode = _mode_from_text(arg_text)
        if algorithm == "ChaCha20" and (_has_none_mode(args) or mode is None):
            mode = "stream"
            evidence.append("ChaCha20 treated as stream cipher semantics")
        primitive = "symmetric_encryption"
        provider = provider or "cryptography"
    else:
        mode = _mode_from_text(arg_text) or _mode_from_api(api, algorithm)

    if api == "PKCS1_OAEP.new":
        algorithm = "RSA-OAEP"
        primitive = "asymmetric_encryption"
        evidence.append("Mapped PKCS1_OAEP wrapper to RSA-OAEP")

    if api in {"hmac.new", "HMAC"}:
        digest = _digest_from_text(arg_text)
        if digest:
            algorithm = f"HMAC-{digest}"
            evidence.append(f"Resolved HMAC digest algorithm: {digest}")

    if api == "rsa.generate_private_key":
        algorithm = "RSA"
        primitive = "asymmetric_key_generation"

    if api == "ec.generate_private_key":
        algorithm = "ECC"
        primitive = "asymmetric_key_generation"
        curve = _curve_from_text(arg_text)
        if curve:
            evidence.append(f"Resolved elliptic curve argument: {curve}")

    if api == "x509.CertificateBuilder":
        algorithm = "X.509"
        primitive = "certificate_management"
        evidence.append("Mapped CertificateBuilder to certificate management")

    padding = _padding_from_text(arg_text)
    key_size = _key_size(finding, algorithm, primitive)
    operation = _operation_for(api, primitive)

    if primitive in {"symmetric_encryption", "authenticated_encryption", "asymmetric_encryption", "cipher_mode"}:
        mode = mode or UNKNOWN
    else:
        mode = None

    if primitive in {"symmetric_encryption", "asymmetric_encryption"}:
        padding = padding or UNKNOWN
    else:
        padding = None

    return NormalizedCrypto(
        algorithm=algorithm,
        primitive=primitive,
        provider=provider,
        mode=mode,
        padding=padding,
        key_size=key_size,
        operation=operation,
        evidence=evidence,
    )


def _inner_cipher_algorithm(text: str) -> str | None:
    patterns = [
        (r"algorithms\.AES\s*\(", "AES"),
        (r"algorithms\.ChaCha20\s*\(", "ChaCha20"),
        (r"algorithms\.ChaCha20Poly1305\s*\(", "ChaCha20-Poly1305"),
        (r"algorithms\.TripleDES\s*\(", "3DES"),
        (r"algorithms\.Camellia\s*\(", "Camellia"),
        (r"algorithms\.SEED\s*\(", "SEED"),
        (r"algorithms\.CAST5\s*\(", "CAST5"),
        (r"algorithms\.CAST6\s*\(", "CAST6"),
    ]
    for pattern, value in patterns:
        if re.search(pattern, text):
            return value
    return None


def _mode_from_text(text: str) -> str | None:
    match = re.search(r"(?:MODE_|modes\.)(ECB|CBC|GCM|CTR|CFB|OFB|EAX|SIV|CCM)", text)
    return match.group(1) if match else None


def _mode_from_api(api: str, algorithm: str) -> str | None:
    for mode in ["ECB", "CBC", "GCM", "CTR", "CFB", "OFB", "EAX", "SIV", "CCM"]:
        if api.endswith(f".{mode}") or algorithm == mode:
            return mode
    return None


def _has_none_mode(args: list[str]) -> bool:
    return any(arg.strip() in {"None", "mode=None"} or "mode=None" in arg for arg in args)


def _padding_from_text(text: str) -> str | None:
    lowered = text.lower()
    if "oaep" in lowered:
        return "OAEP"
    if "pss" in lowered:
        return "PSS"
    if "pkcs1v15" in lowered or "pkcs1_v1_5" in lowered:
        return "PKCS1v15"
    if "pkcs7" in lowered:
        return "PKCS7"
    return None


def _digest_from_text(text: str) -> str | None:
    normalized = text.lower().replace("_", "-")
    if "sha256" in normalized or "sha-256" in normalized:
        return "SHA-256"
    if "sha512" in normalized or "sha-512" in normalized:
        return "SHA-512"
    if "sha1" in normalized or "sha-1" in normalized:
        return "SHA-1"
    if "md5" in normalized:
        return "MD5"
    return None


def _curve_from_text(text: str) -> str | None:
    match = re.search(r"SECP(256|384|521)R1", text)
    return f"SECP{match.group(1)}R1" if match else None


def _key_size(finding: CryptoFinding, algorithm: str, primitive: str) -> int | str | None:
    signal_size = finding.context.get("signals", {}).get("key_size")
    if isinstance(signal_size, int):
        if algorithm == "RSA" and 512 <= signal_size <= 8192:
            return signal_size
        if algorithm != "RSA":
            return signal_size

    for argument in finding.arguments:
        numbers = [int(match) for match in re.findall(r"\b(?:key_size\s*=\s*)?(\d{2,5})\b", str(argument))]
        for number in numbers:
            if algorithm == "RSA" and 512 <= number <= 8192:
                return number
            if algorithm in {"AES", "ChaCha20", "Fernet", "HMAC", "HMAC-SHA-256", "HMAC-SHA-512"}:
                if number in {16, 24, 32}:
                    return number * 8
                if number in {128, 192, 256, 384, 512}:
                    return number
            if primitive == "key_derivation" and number in {16, 24, 32, 48, 64}:
                return number * 8

    if primitive in {
        "symmetric_encryption",
        "authenticated_encryption",
        "asymmetric_encryption",
        "key_derivation",
        "message_authentication",
        "asymmetric_key_generation",
    }:
        return UNKNOWN
    return None


def _operation_for(api: str, primitive: str) -> str:
    lowered = api.lower()
    if "decrypt" in lowered:
        return "decryption"
    if "verify" in lowered:
        return "verification"
    if "sign" in lowered:
        return "signing"
    return {
        "symmetric_encryption": "encryption",
        "authenticated_encryption": "encryption",
        "asymmetric_encryption": "encryption",
        "symmetric_key_generation": "key_generation",
        "asymmetric_key_generation": "key_generation",
        "key_derivation": "key_derivation",
        "hash": "digest",
        "message_authentication": "authentication",
        "random_generation": "random_generation",
        "cipher_mode": "mode_selection",
        "certificate_management": "certificate_management",
        "digital_signature": "signing",
    }.get(primitive, primitive)
