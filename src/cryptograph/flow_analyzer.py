"""Build normalized CBOM flow fields from graph/context signals."""

from __future__ import annotations

from typing import Any

from cryptograph.algorithm_normalizer import NormalizedCrypto
from cryptograph.models import CryptoFinding

UNKNOWN = "unknown"

KEYED_PRIMITIVES = {
    "symmetric_encryption",
    "authenticated_encryption",
    "asymmetric_encryption",
    "key_derivation",
    "message_authentication",
}

DATA_PRIMITIVES = KEYED_PRIMITIVES | {"hash", "password_hashing", "password_verification"}


def build_flow(finding: CryptoFinding, normalized: NormalizedCrypto) -> dict[str, Any]:
    """Return stable flow schema with unknown/null semantics."""
    argument_signals = finding.context.get("signals", {}).get("arguments", [])
    sources = finding.context.get("signals", {}).get("sources", [])
    sink = finding.context.get("signals", {}).get("sink") or {}

    flow = {
        "key_source": _source_for_role("key", argument_signals, sources, normalized),
        "data_source": _source_for_role("data", argument_signals, sources, normalized),
        "iv_source": _source_for_role("iv", argument_signals, sources, normalized),
        "nonce_source": _source_for_role("nonce", argument_signals, sources, normalized),
        "salt_source": _source_for_role("salt", argument_signals, sources, normalized),
        "randomness_source": _source_for_role("randomness", argument_signals, sources, normalized),
        "sink": {
            "type": sink.get("classification") or _default_sink_type(normalized),
            "id": sink.get("sink_id") or _default_sink_id(normalized),
        },
    }
    dataflow = finding.context.get("dataflow", {})
    if dataflow.get("sources_reaching_sink"):
        flow["variable_flows"] = dataflow["sources_reaching_sink"]
    return flow


def _source_for_role(
    role: str,
    argument_signals: list[dict[str, Any]],
    sources: list[dict[str, Any]],
    normalized: NormalizedCrypto,
) -> str | None:
    if not _role_applies(role, normalized):
        return None

    if role == "key" and normalized.primitive == "key_derivation":
        return "derived_from_kdf"

    if role == "key" and normalized.primitive in {"asymmetric_key_generation", "symmetric_key_generation"}:
        return "generated_random"

    matches = _signals_for_role(role, argument_signals)
    if role == "nonce" and not matches and "chacha" not in normalized.algorithm.lower():
        return None
    classifications = [source.get("classification") for source in sources]

    if role == "randomness" and (
        normalized.primitive == "random_generation" or "generated_random" in classifications
    ):
        return "generated_random"

    if role == "randomness" and normalized.primitive in {"asymmetric_key_generation", "symmetric_key_generation"}:
        return "generated_random"

    if any(_literal_for_role(signal, role) for signal in matches):
        return "hardcoded_constant"

    for signal in matches:
        source = _source_from_signal(signal, role)
        if source != UNKNOWN:
            return source

    if role == "key" and "key_material" in classifications:
        return "external_input"
    if role == "data" and "user_input" in classifications:
        return "external_input"
    return UNKNOWN


def _signals_for_role(role: str, argument_signals: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        signal
        for signal in argument_signals
        if signal.get("role") == role or role in (signal.get("role_values") or {})
    ]


def _literal_for_role(signal: dict[str, Any], role: str) -> bool:
    if signal.get("role") == role:
        return bool(signal.get("is_literal"))
    role_literal = (signal.get("role_literals") or {}).get(role) or {}
    return bool(role_literal.get("is_literal"))


def _source_from_signal(signal: dict[str, Any], role: str) -> str:
    role_values = signal.get("role_values") or {}
    semantic_value = str(role_values.get(role) or signal.get("semantic_value") or signal.get("value") or "")
    semantic_lower = semantic_value.lower()

    if semantic_lower.startswith("self.") or ".self." in semantic_lower:
        return "object_property"

    role_origins = signal.get("role_origins") or {}
    origin = role_origins.get(role) if role in role_origins else signal.get("assignment_origin")
    origin = origin or {}

    if origin.get("kind") == "function_parameter":
        return "function_parameter"

    if origin.get("kind") == "assignment":
        expression = str(origin.get("expression", "")).lower()
        if _is_generated_random_expression(expression):
            return "generated_random"
        if _is_kdf_expression(expression):
            return "derived_from_kdf"
        if origin.get("is_literal"):
            return "hardcoded_constant"
        if expression.startswith("self.") or ".self." in expression:
            return "object_property"
        if _is_derived_expression(expression):
            return "derived_value"
        if origin.get("is_call"):
            return "return_value"
        return "local_assignment"

    if _is_generated_random_expression(semantic_lower):
        return "generated_random"
    if _is_kdf_expression(semantic_lower):
        return "derived_from_kdf"
    if signal.get("is_literal") and signal.get("role") == role:
        return "hardcoded_constant"
    return UNKNOWN


def _is_generated_random_expression(expression: str) -> bool:
    return any(
        token in expression
        for token in [
            "os.urandom",
            "urandom",
            "secrets.",
            "token_bytes",
            "token_hex",
            "token_urlsafe",
            "randbytes",
            "random_serial_number",
        ]
    )


def _is_kdf_expression(expression: str) -> bool:
    return any(token in expression for token in ["derive", "kdf", "pbkdf", "scrypt", "argon", "hkdf", "bcrypt.kdf"])


def _is_derived_expression(expression: str) -> bool:
    return any(token in expression for token in ["+", "^", "hash", "sha", "digest", "encode", "decode", "[", "]", "concat"])


def _role_applies(role: str, normalized: NormalizedCrypto) -> bool:
    primitive = normalized.primitive
    if role == "key":
        return primitive in KEYED_PRIMITIVES or "key_generation" in primitive
    if role == "data":
        return primitive in DATA_PRIMITIVES
    if role == "iv":
        return (
            primitive in {"symmetric_encryption", "authenticated_encryption", "cipher_mode"}
            and normalized.mode not in {None, "ECB", "stream"}
            and "chacha" not in normalized.algorithm.lower()
        )
    if role == "nonce":
        return primitive in {"symmetric_encryption", "authenticated_encryption", "cipher_mode"} and (
            normalized.mode in {"stream", "GCM", "CTR", "CCM", "EAX", "SIV"} or "chacha" in normalized.algorithm.lower()
        )
    if role == "salt":
        return primitive in {"key_derivation", "password_hashing"}
    if role == "randomness":
        return primitive in {"random_generation", "symmetric_key_generation", "asymmetric_key_generation", "key_derivation"}
    return False


def _default_sink_type(normalized: NormalizedCrypto) -> str:
    if normalized.primitive in {
        "symmetric_encryption",
        "authenticated_encryption",
        "asymmetric_encryption",
        "key_derivation",
        "hash",
        "message_authentication",
    }:
        return "cryptographic_output"
    return UNKNOWN


def _default_sink_id(normalized: NormalizedCrypto) -> str | None:
    return {
        "symmetric_encryption": "encryption_output",
        "authenticated_encryption": "encryption_output",
        "asymmetric_encryption": "encryption_output",
        "key_derivation": "derived_key",
        "hash": "hash_digest",
        "message_authentication": "mac_tag",
    }.get(normalized.primitive)
