"""Risk scoring engine for cryptographic assets.

Implements a multi-factor risk scoring system based on:
- Algorithm strength and cryptographic maturity
- Mode of operation and implementation patterns
- Key derivation parameters
- Source of cryptographic material (hardcoded, derived, generated)
- Known attack vectors and common implementation flaws
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

RiskLevel = Literal["low", "medium", "high", "critical"]
Confidence = float


@dataclass
class RiskScore:
    """Structured risk assessment for a cryptographic asset."""

    level: RiskLevel
    confidence: float  # 0.0-1.0
    tags: list[str]
    derivation: dict[str, Any]  # How we arrived at this risk level


class RiskEngine:
    """Computes risk scores for cryptographic findings."""

    # Algorithm base risk levels (independent of usage)
    ALGORITHM_RISK = {
        # Broken/deprecated hashes
        "MD5": "high",
        "SHA-1": "high",
        # Legacy ciphers
        "DES": "high",
        "3DES": "high",
        # Insecure modes
        "ECB": "high",
        # Weak random
        "Random": "high",  # Python's random module
        # Modern secure algorithms
        "AES": "low",
        "ChaCha20": "low",
        "ChaCha20-Poly1305": "low",
        "SHA-256": "low",
        "SHA-512": "low",
        "SHA3-256": "low",
        "BLAKE2b": "low",
        "BLAKE2s": "low",
        "Argon2": "low",
        "Scrypt": "low",
        "PBKDF2": "low",
        "CSPRNG": "low",
        "Fernet": "low",
        "RSA": "low",  # Base level; escalated if key < 2048
        "ECC": "low",
        "ECDSA": "low",
        "EdDSA": "low",
        "HMAC": "low",
    }

    # Mode risk levels (modifiers when algorithm is cipher)
    MODE_RISK = {
        "ECB": "high",  # Always insecure
        "CBC": "low",  # Review condition; not automatically vulnerable
        "CTR": "low",  # Requires unique IV
        "OFB": "low",  # Requires unique IV
        "CFB": "low",
        "GCM": "low",  # AEAD
        "EAX": "low",  # AEAD
        "SIV": "low",  # AEAD
        "CCM": "low",  # AEAD
    }

    # Provider trust levels
    PROVIDER_TRUST = {
        "cryptography": 0.95,  # Audited, well-maintained
        "python-stdlib": 0.90,  # Standard library (good)
        "pycryptodome": 0.85,  # Well-maintained, but less audited
        "bcrypt": 0.95,  # Specialized, audited
        "nacl": 0.95,  # Audited, modern
        "paramiko": 0.80,  # SSH library
        "M2Crypto": 0.70,  # Legacy, less maintained
    }

    def score(
        self,
        algorithm: str,
        primitive: str,
        provider: str | None,
        arguments: list[str],
        api_name: str,
        context: dict[str, Any],
    ) -> RiskScore:
        """Compute risk score for a cryptographic asset.

        Args:
            algorithm: Algorithm name (AES, RSA, SHA-256, etc.)
            primitive: Primitive type (symmetric_encryption, key_derivation, etc.)
            provider: Provider name (cryptography, pycryptodome, etc.)
            arguments: Function arguments (may contain mode, key size, etc.)
            api_name: Full API name for pattern matching
            context: Additional context (signals, flow, etc.)

        Returns:
            RiskScore with level, confidence, tags, and derivation.
        """
        derivation: dict[str, Any] = {}

        # 1. Base level from algorithm
        base_level = self.ALGORITHM_RISK.get(algorithm, "low")
        derivation["base_algorithm_risk"] = base_level

        # 2. Mode-specific escalation (for block ciphers)
        mode = context.get("signals", {}).get("mode")
        if mode:
            mode_level = self.MODE_RISK.get(mode, "low")
            if self._risk_higher(mode_level, base_level):
                base_level = mode_level
                derivation["mode_escalation"] = {
                    "mode": mode,
                    "escalated_from": derivation["base_algorithm_risk"],
                    "reason": f"{mode} mode has known vulnerabilities",
                }

        # 3. Context-specific modifiers
        tags: list[str] = []
        confidence = 0.8

        # Check for weak key size (RSA < 2048, ECC < 256)
        key_size = context.get("signals", {}).get("key_size")
        if isinstance(key_size, int):
            if algorithm in ("RSA", "RSA-OAEP") and key_size < 2048:
                tags.append("weak_key_size")
                base_level = "high" if key_size < 1024 else "medium"
                derivation["key_size_downgrade"] = {
                    "size": key_size,
                    "minimum": 2048,
                    "reason": "RSA key size below minimum recommended",
                }
            elif algorithm in ("ECC", "ECDSA", "EdDSA") and key_size < 256:
                tags.append("weak_key_size")
                if base_level == "low":
                    base_level = "medium"

        # Check for weak PBKDF2 iterations
        if algorithm == "PBKDF2":
            iterations = self._extract_pbkdf2_iterations(arguments)
            if iterations and iterations < 100000:
                tags.append("low_iteration_count")
                base_level = "medium"
                derivation["pbkdf2_weak_iterations"] = {
                    "iterations": iterations,
                    "minimum": 100000,
                }
                confidence = 0.85

        # Check for ECB mode (always critical)
        if mode == "ECB" or algorithm == "ECB":
            tags.append("ecb_mode_detected")
            base_level = "critical"
            confidence = 0.98

        if mode == "CBC" and algorithm in {"AES", "3DES", "DES", "Cipher"}:
            flow = context.get("flow", {})
            iv_source = flow.get("iv_source")
            tags.append("cbc_requires_authentication_review")
            derivation["cbc_review"] = {
                "mode": "CBC",
                "iv_source": iv_source or "unknown",
                "reason": "CBC is acceptable only with fresh IV and authentication",
            }
            if iv_source in {None, "unknown", "hardcoded_constant"}:
                base_level = "medium"
                tags.append("iv_source_unresolved")

        # Check for deprecated algorithms
        if algorithm in ("DES", "3DES", "MD5", "SHA-1"):
            tags.append("deprecated_algorithm")
            if base_level != "high":
                base_level = "high"

        # Check for hardcoded material
        signals = context.get("signals", {})
        sources = signals.get("sources", [])
        argument_literals = [
            signal for signal in signals.get("arguments", [])
            if signal.get("is_literal") and signal.get("role") in {"key", "iv", "salt", "data"}
        ]
        if argument_literals:
            tags.append("hardcoded_material")
            if base_level == "low":
                base_level = "medium"
            derivation["hardcoded_material"] = {
                "argument_indexes": [signal.get("index") for signal in argument_literals],
                "reason": "Literal cryptographic material detected",
            }

        # Check for weak random source
        if api_name in ("random.random", "random.randint", "random.choice"):
            tags.append("weak_random_source")
            base_level = "high"
            derivation["weak_random"] = {
                "api": api_name,
                "reason": "Non-cryptographic random for crypto operation",
            }

        # 4. Provider trust adjustment (confidence, not level)
        if provider:
            provider_trust = self.PROVIDER_TRUST.get(provider, 0.75)
            confidence *= provider_trust
        else:
            confidence *= 0.70  # Reduced for unknown provider

        # 5. Call graph depth (confidence modifier)
        call_graph = context.get("control", {}).get("call_graph", {})
        call_chain = call_graph.get("call_chain", [])
        if len(call_chain) > 3:
            tags.append("deep_call_chain")
            confidence *= 0.95  # Slightly harder to trace

        # Normalize confidence
        confidence = min(0.99, max(0.5, confidence))

        return RiskScore(
            level=base_level,
            confidence=confidence,
            tags=tags,
            derivation=derivation,
        )

    def _risk_higher(self, left: RiskLevel, right: RiskLevel) -> bool:
        """Check if left risk is higher than right."""
        order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        return order.get(left, 0) > order.get(right, 0)

    def _extract_pbkdf2_iterations(self, arguments: list[str]) -> int | None:
        """Try to extract iteration count from PBKDF2 arguments."""
        for arg in arguments:
            if "iterations" in arg.lower():
                # Format might be "iterations=100000" or similar
                try:
                    parts = arg.split("=")
                    if len(parts) == 2:
                        return int(parts[1])
                except ValueError:
                    pass
        return None

    def risk_tag_explanation(self, tag: str) -> str:
        """Provide human-readable explanation for a risk tag."""
        explanations = {
            "weak_key_size": "RSA key size below 2048 bits or ECC below 256 bits",
            "low_iteration_count": "PBKDF2 iteration count below 100,000",
            "ecb_mode_detected": "ECB mode detected; identical plaintexts produce identical ciphertexts",
            "deprecated_algorithm": "Algorithm is deprecated (e.g., DES, MD5, SHA-1)",
            "hardcoded_material": "Cryptographic material may be hardcoded",
            "weak_random_source": "Weak randomness source for cryptographic operation",
            "deep_call_chain": "Multi-level function call; context harder to infer",
            "high_risk_crypto_usage": "Known risky usage pattern detected",
            "iv_reuse_risk": "Potential nonce/IV reuse vulnerability",
            "padding_oracle_risk": "Potential padding oracle vulnerability",
            "unencrypted_flow": "Data may flow without encryption",
        }
        return explanations.get(tag, f"Risk tag: {tag}")


def compute_risk_score(
    algorithm: str,
    primitive: str,
    provider: str | None,
    arguments: list[str],
    api_name: str,
    context: dict[str, Any],
) -> tuple[RiskLevel, float, list[str]]:
    """Convenience function to compute risk score.

    Returns:
        (risk_level, confidence, tags)
    """
    engine = RiskEngine()
    score = engine.score(algorithm, primitive, provider, arguments, api_name, context)
    return score.level, score.confidence, score.tags
