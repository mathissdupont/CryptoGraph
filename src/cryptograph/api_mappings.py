"""Normalize the flat and per-language API mapping formats."""
from __future__ import annotations

from typing import Any


def normalize_mappings(raw_mappings: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Support both mapping schemas:

    1) Flat schema: {"API": {"algorithm": ..., "primitive": ...}}
    2) Language schema: {"language": "x", "mappings": [{"api_pattern": ..., ...}]}
    """
    if not isinstance(raw_mappings, dict):
        return {}

    if isinstance(raw_mappings.get("mappings"), list):
        normalized: dict[str, dict[str, Any]] = {}
        for entry in raw_mappings.get("mappings", []):
            if not isinstance(entry, dict):
                continue
            api_pattern = entry.get("api_pattern")
            if not api_pattern:
                continue
            normalized[str(api_pattern)] = {
                "algorithm": entry.get("algorithm", "unknown"),
                "primitive": _normalize_primitive(str(entry.get("primitive", "unknown"))),
                "provider": entry.get("provider"),
            }
        return normalized

    # already flat format
    normalized = {}
    for api_name, payload in raw_mappings.items():
        if not isinstance(payload, dict):
            continue
        normalized[str(api_name)] = {
            "algorithm": payload.get("algorithm", "unknown"),
            "primitive": _normalize_primitive(str(payload.get("primitive", "unknown"))),
            "provider": payload.get("provider"),
        }
    return normalized


def _normalize_primitive(primitive: str) -> str:
    mapping = {
        "kdf": "key_derivation",
        "password_hashing": "key_derivation",
        "key_generation": "asymmetric_key_generation",
    }
    return mapping.get(primitive, primitive)
