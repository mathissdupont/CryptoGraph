from __future__ import annotations

from typing import Any


def assess_pqc(asset: dict[str, Any]) -> dict[str, Any]:
    """Assess PQC posture for a cryptographic asset.

    Returns a normalized structure that can be embedded into labels.
    """
    inp = asset.get("input", {})
    crypto_meta = inp.get("crypto_metadata", {}) if isinstance(inp, dict) else {}
    algo = str(crypto_meta.get("algorithm", "unknown")).upper()
    primitive = str(crypto_meta.get("primitive", "unknown")).lower()
    key_size = crypto_meta.get("key_size")

    pqc_ready_algorithms = {
        "ML-KEM", "KYBER", "ML-DSA", "DILITHIUM", "SPHINCS+", "SPHINCS", "FALCON", "XMSS"
    }
    broken_in_qc = {
        "RSA", "ECC", "ECDSA", "ED25519", "ED448", "ECDH", "DH", "DSA"
    }

    # Post-quantum native algorithms
    if algo in pqc_ready_algorithms:
        return {
            "compatible": True,
            "status": "pqc-native",
            "migration_priority": "none",
            "reasoning": f"{algo} is a post-quantum or hash-based algorithm family.",
            "recommended": ["Keep implementation up-to-date with NIST profiles and vetted libraries."],
        }

    # Public-key families known to be broken by large-scale quantum computers
    if algo in broken_in_qc or primitive in {"asymmetric_encryption", "asymmetric_key_generation", "digital_signature"}:
        return {
            "compatible": False,
            "status": "quantum-vulnerable",
            "migration_priority": "high",
            "reasoning": f"{algo} relies on classical public-key hardness assumptions vulnerable to quantum attacks.",
            "recommended": [
                "Plan migration to ML-KEM (key exchange/KEM) and ML-DSA or SPHINCS+ (signatures).",
                "Use hybrid deployment (classical + PQC) during transition.",
            ],
        }

    # Symmetric and hash primitives survive quantum better but may need stronger params
    if primitive in {"hash", "message_authentication", "random_generation", "symmetric_encryption", "authenticated_encryption", "key_derivation"}:
        recs = ["Prefer AES-256 and SHA-384/SHA-512 for long-term security margins."]
        if isinstance(key_size, int) and key_size < 256 and primitive in {"symmetric_encryption", "authenticated_encryption"}:
            recs.append("Increase symmetric key size to 256-bit where possible.")
        return {
            "compatible": True,
            "status": "quantum-resilient-with-parameters",
            "migration_priority": "medium",
            "reasoning": "Symmetric/hash primitives are generally quantum-resilient with stronger parameters.",
            "recommended": recs,
        }

    return {
        "compatible": False,
        "status": "unknown",
        "migration_priority": "medium",
        "reasoning": "Unable to determine PQC posture from available metadata.",
        "recommended": ["Review algorithm metadata and map to PQC policy catalog."],
    }


def simulate_label(asset: dict[str, Any]) -> dict[str, Any]:
    """Deterministic baseline labeler used when no external LLM is configured."""
    inp = asset.get("input", {})
    meta = inp.get("metadata", {}) if isinstance(inp, dict) else {}
    crypto_meta = inp.get("crypto_metadata", {}) if isinstance(inp, dict) else {}
    algo = str(crypto_meta.get("algorithm", "Unknown")).upper()
    mode = str(crypto_meta.get("mode", "")).upper()

    label: dict[str, Any] = {
        "schema_version": "1.1",
        "risk_level": "info",
        "confidence": 0.6,
        "reasoning": "",
        "remediation": "",
        "references": [],
        "language": meta.get("detected_language", "unknown"),
    }

    if mode == "ECB":
        label.update(
            {
                "risk_level": "critical",
                "confidence": 0.95,
                "reasoning": "ECB mode is insecure; plaintext patterns leak into ciphertext.",
                "remediation": "Replace ECB with GCM, CTR, or CBC+HMAC. Use unique IV/nonce.",
                "references": ["NIST SP 800-38A", "CWE-327"],
            }
        )
    elif algo in {"MD5", "SHA-1", "SHA1"}:
        label.update(
            {
                "risk_level": "high",
                "confidence": 0.9,
                "reasoning": "Cryptographically broken hash algorithm; susceptible to collision attacks.",
                "remediation": "Replace with SHA-256, SHA-512, or SHA3-256.",
                "references": ["NIST", "CWE-327"],
            }
        )
    elif algo == "RSA" and isinstance(crypto_meta.get("key_size"), int) and crypto_meta.get("key_size") < 2048:
        label.update(
            {
                "risk_level": "high",
                "confidence": 0.88,
                "reasoning": f"RSA key size {crypto_meta.get('key_size')} bits is too small.",
                "remediation": "Use at least 2048-bit keys (3072/4096 preferred).",
                "references": ["NIST SP 800-56B", "CWE-326"],
            }
        )
    elif mode in {"GCM", "CHACHA20-POLY1305"}:
        label.update(
            {
                "risk_level": "low",
                "confidence": 0.85,
                "reasoning": "AEAD mode with authenticated encryption; best practice.",
                "remediation": "Keep AEAD and ensure nonce uniqueness per key.",
                "references": ["NIST SP 800-38D"],
            }
        )
    elif algo in {"ARGON2", "BCRYPT", "SCRYPT"}:
        label.update(
            {
                "risk_level": "low",
                "confidence": 0.84,
                "reasoning": f"{algo} is a modern password hashing/KDF family.",
                "remediation": "Review memory/time/cost parameters against current guidance.",
                "references": ["OWASP Password Storage Cheat Sheet"],
            }
        )
    else:
        label.update(
            {
                "risk_level": "medium",
                "confidence": 0.65,
                "reasoning": f"Algorithm {algo} (mode: {mode or 'N/A'}) requires context review.",
                "remediation": "Confirm algorithm/mode/params align with policy and threat model.",
            }
        )

    pqc = assess_pqc(asset)
    label["pqc"] = pqc
    label["pqc_compatible"] = pqc.get("compatible", False)
    return label
