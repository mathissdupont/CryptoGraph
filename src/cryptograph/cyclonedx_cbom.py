from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


UNKNOWN = "unknown"


def convert_to_cyclonedx_cbom(custom_cbom: dict[str, Any]) -> dict[str, Any]:
    """Convert CryptoGraph's analysis-rich CBOM into a CycloneDX hybrid CBOM.

    The standard CycloneDX layer stays small and interoperable. CryptoGraph-specific
    context, flow, risk, inference, rules, graph context, and evidence live under
    each cryptographic component's custom ``analysis`` extension.
    """
    assets = _assets(custom_cbom)
    provider_components = _provider_components(assets)
    asset_components = [_asset_component(asset) for asset in assets]

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": _metadata(custom_cbom),
        "components": [*asset_components, *provider_components],
        "dependencies": _dependencies(assets, provider_components),
    }


def _assets(custom_cbom: dict[str, Any]) -> list[dict[str, Any]]:
    raw_assets = custom_cbom.get("cryptographic_assets", [])
    return [asset for asset in raw_assets if isinstance(asset, dict)]


def _metadata(custom_cbom: dict[str, Any]) -> dict[str, Any]:
    source_metadata = custom_cbom.get("metadata", {})
    if not isinstance(source_metadata, dict):
        source_metadata = {}
    timestamp = source_metadata.get("generated_at") or datetime.now(UTC).isoformat()
    metadata = {
        "timestamp": timestamp,
        "component": {
            "type": "application",
            "name": "cryptograph-analysis",
            "version": "1.0",
        },
        "tools": [
            {
                "vendor": "CryptoGraph",
                "name": source_metadata.get("tool", "CryptoGraph"),
                "version": str(custom_cbom.get("spec_version", "1.0")),
            }
        ],
    }
    properties = _properties(
        {
            "cryptograph:source": source_metadata.get("source"),
            "cryptograph:backend": source_metadata.get("backend"),
            "cryptograph:run_id": source_metadata.get("run_id"),
            "cryptograph:source_language": source_metadata.get("source_language"),
        }
    )
    if properties:
        metadata["properties"] = properties
    return metadata


def _asset_component(asset: dict[str, Any]) -> dict[str, Any]:
    crypto = _dict(asset.get("crypto_metadata"))
    usage = _dict(asset.get("usage"))
    algorithm = _known(crypto.get("algorithm"), fallback="unknown-algorithm")
    operation = _known(usage.get("operation"))
    asset_id = _known(asset.get("asset_id"), fallback=_asset_ref_from(algorithm, asset))

    algorithm_properties = {
        "cryptoFunctions": _crypto_functions(operation),
    }
    _put_if_present(algorithm_properties, "primitive", crypto.get("primitive"))
    _put_if_present(algorithm_properties, "parameterSetIdentifier", _parameter_set_identifier(crypto))

    component = {
        "type": "cryptographic-asset",
        "name": algorithm,
        "bom-ref": asset_id,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": algorithm_properties,
        },
        "analysis": {
            "context": _clean(_dict(asset.get("context"))),
            "flow": _clean(_dict(asset.get("flow"))),
            "risk": _risk(asset),
            "inference": _clean(_dict(asset.get("inference"))),
            "rules": _clean(_list(asset.get("rules"))),
            "graph_context": _clean(_dict(asset.get("graph_context"))),
            "evidence": {"summary": _clean(_evidence_summary(asset))},
        },
    }

    provider = _known(crypto.get("provider"))
    if provider != UNKNOWN:
        component["properties"] = [{"name": "cryptograph:provider", "value": provider}]
    return component


def _provider_components(assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    providers = sorted(
        {
            _known(_dict(asset.get("crypto_metadata")).get("provider"))
            for asset in assets
            if _known(_dict(asset.get("crypto_metadata")).get("provider")) != UNKNOWN
        }
    )
    return [
        {
            "type": "library",
            "name": provider,
            "bom-ref": _provider_ref(provider),
            "properties": [{"name": "cryptograph:component_role", "value": "crypto-provider"}],
        }
        for provider in providers
    ]


def _dependencies(assets: list[dict[str, Any]], providers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    provider_refs = {component["name"]: component["bom-ref"] for component in providers}
    dependencies: list[dict[str, Any]] = []
    for asset in assets:
        crypto = _dict(asset.get("crypto_metadata"))
        provider = _known(crypto.get("provider"))
        depends_on = [provider_refs[provider]] if provider in provider_refs else []
        dependencies.append({"ref": _known(asset.get("asset_id"), fallback=_asset_ref_from(_known(crypto.get("algorithm")), asset)), "dependsOn": depends_on})
    for component in providers:
        dependencies.append({"ref": component["bom-ref"], "dependsOn": []})
    return dependencies


def _risk(asset: dict[str, Any]) -> dict[str, Any]:
    risk = _dict(asset.get("risk"))
    result: dict[str, Any] = {"tags": _clean(_list(risk.get("tags")))}
    _put_if_present(result, "level", risk.get("level"))
    _put_if_present(result, "confidence", risk.get("confidence"))
    return result


def _evidence_summary(asset: dict[str, Any]) -> dict[str, Any]:
    evidence = _dict(asset.get("evidence"))
    summary = evidence.get("summary")
    if isinstance(summary, dict):
        return summary
    return {
        key: value
        for key, value in evidence.items()
        if key
        not in {
            "debug",
            "raw_node_id",
            "argument_signals",
            "graph_edges",
            "graph_edge_kinds",
            "full_arguments",
        }
    }


def _parameter_set_identifier(crypto: dict[str, Any]) -> str | None:
    mode = _known(crypto.get("mode"))
    if mode != UNKNOWN:
        return mode
    key_size = crypto.get("key_size")
    if key_size not in (None, "", UNKNOWN):
        return f"key_size:{key_size}"
    return None


def _crypto_functions(operation: str) -> list[str]:
    mapping = {
        "encryption": "encrypt",
        "decryption": "decrypt",
        "encrypt": "encrypt",
        "decrypt": "decrypt",
        "digest": "digest",
        "hash": "digest",
        "hashing": "digest",
        "key_derivation": "derive",
        "derive": "derive",
        "key_generation": "generate",
        "asymmetric_key_generation": "generate",
        "symmetric_key_generation": "generate",
        "random_generation": "generate",
        "random_selection": "generate",
        "message_authentication": "authenticate",
        "authentication": "authenticate",
        "digital_signature": "sign",
        "signing": "sign",
        "verification": "verify",
        "token_generation": "generate",
        "token_verification": "verify",
    }
    if operation == UNKNOWN:
        return []
    return [mapping.get(operation, operation)]


def _asset_ref_from(algorithm: str, asset: dict[str, Any]) -> str:
    location = _dict(asset.get("context")).get("function") or _dict(asset.get("context")).get("file") or "asset"
    return f"crypto:{algorithm}:{location}"


def _provider_ref(provider: str) -> str:
    return f"crypto-provider:{provider.lower().replace(' ', '-')}"


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _known(value: Any, fallback: str = UNKNOWN) -> str:
    if value in (None, ""):
        return fallback
    return str(value)


def _put_if_present(target: dict[str, Any], key: str, value: Any) -> None:
    if value in (None, "", UNKNOWN):
        return
    target[key] = value


def _properties(values: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {"name": name, "value": str(value)}
        for name, value in values.items()
        if value not in (None, "", UNKNOWN)
    ]


def _clean(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned = {
            key: _clean(item)
            for key, item in value.items()
            if not _is_noisy_unknown(item)
        }
        return {
            key: item
            for key, item in cleaned.items()
            if item not in ({}, [])
        }
    if isinstance(value, list):
        return [
            cleaned
            for item in value
            if not _is_noisy_unknown(item)
            for cleaned in [_clean(item)]
            if cleaned not in ({}, [])
        ]
    return value


def _is_noisy_unknown(value: Any) -> bool:
    if value in (None, "", UNKNOWN, "unknown_file", "unknown_function"):
        return True
    if isinstance(value, str) and value.startswith("UNKNOWN."):
        return True
    return False
