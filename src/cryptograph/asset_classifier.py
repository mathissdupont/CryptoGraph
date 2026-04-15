"""Classify discovered crypto-like objects by CBOM relevance."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from cryptograph.algorithm_normalizer import NormalizedCrypto
from cryptograph.models import CryptoFinding

AssetClass = Literal["primary_asset", "supporting_artifact", "ignore"]


@dataclass(frozen=True)
class AssetClassification:
    asset_class: AssetClass
    reason: str


PRIMARY_PRIMITIVES = {
    "symmetric_encryption",
    "authenticated_encryption",
    "asymmetric_encryption",
    "symmetric_key_generation",
    "asymmetric_key_generation",
    "key_derivation",
    "hash",
    "message_authentication",
    "random_generation",
    "digital_signature",
    "certificate_management",
    "password_hashing",
    "password_verification",
}

SUPPORTING_PRIMITIVES = {
    "cipher_mode",
    "certificate_attribute",
    "certificate_extension",
    "certificate_request",
    "key_serialization",
    "crypto_backend",
    "random_selection",
    "token_generation",
    "token_verification",
}


def classify_asset(finding: CryptoFinding, normalized: NormalizedCrypto) -> AssetClassification:
    """Label a finding as a primary asset, supporting artifact, or ignorable."""
    primitive = normalized.primitive
    api = finding.api_name
    algorithm = normalized.algorithm

    if primitive in PRIMARY_PRIMITIVES:
        return AssetClassification("primary_asset", f"{primitive} is a cryptographic operation")

    if primitive in SUPPORTING_PRIMITIVES:
        return AssetClassification("supporting_artifact", f"{primitive} supports primary crypto analysis")

    if api.startswith("x509.") or algorithm.startswith("X.509-"):
        return AssetClassification("supporting_artifact", "X.509 metadata object, not a cryptographic operation")

    if primitive in {"framework_plumbing", "crypto_backend"} or algorithm in {"Backend", "OpenSSL-Backend"}:
        return AssetClassification("ignore", "Framework/backend plumbing")

    return AssetClassification("supporting_artifact", "Crypto-related object without primary operation semantics")
