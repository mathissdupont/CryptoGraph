"""Refactored CBOM builder with improved risk scoring, rule filtering, and explainability."""

from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from cryptograph.algorithm_normalizer import NormalizedCrypto, normalize_finding
from cryptograph.asset_classifier import AssetClassification, classify_asset
from cryptograph.flow_analyzer import build_flow
from cryptograph.inference_explainer import build_inference_explanations, explanation_summary
from cryptograph.models import CryptoFinding, NormalizedGraph
from cryptograph.risk_engine import RiskEngine
from cryptograph.rule_engine import RuleEngine

UNKNOWN = "unknown"


def build_cbom(
    findings: list[CryptoFinding],
    source: str,
    backend: str,
    graph: NormalizedGraph | None = None,
    run_id: str | None = None,
    rules_config: dict[str, Any] | None = None,
) -> dict:
    """Build clean, explainable CBOM with improved risk scoring and rule filtering.

    Args:
        findings: List of cryptographic findings
        source: Source code path
        backend: Analysis backend name
        graph: Optional normalized code property graph
        run_id: Unique run identifier
        rules_config: Rule configuration for conditional filtering

    Returns:
        CBOM dictionary with improved structure
    """
    if rules_config is None:
        rules_config = {"rules": []}

    rule_engine = RuleEngine(rules_config)
    risk_engine = RiskEngine()

    classified = [_classify_for_output(finding) for finding in findings]
    primary = [item for item in classified if item[2].asset_class == "primary_asset"]
    supporting = [item for item in classified if item[2].asset_class == "supporting_artifact"]
    ignored = [item for item in classified if item[2].asset_class == "ignore"]
    primary_assets = [
        _asset_from_finding(finding, normalized, classification, rule_engine, risk_engine)
        for finding, normalized, classification in primary
    ]
    supporting_artifacts = [
        _asset_from_finding(finding, normalized, classification, rule_engine, risk_engine)
        for finding, normalized, classification in supporting
    ]

    return {
        "cbom_format": "cryptograph-custom-v2",
        "spec_version": "1.0",
        "metadata": {
            "tool": "CryptoGraph",
            "generated_at": datetime.now(UTC).isoformat(),
            "source": source,
            "backend": backend,
            "run_id": run_id,
            "source_language": "python",
            "schema_note": (
                "Refactored CBOM v2: Improved risk scoring, "
                "conditional rule filtering, and explainability"
            ),
        },
        "analysis": {
            "scope": {"input": source, "language": "python", "backend": backend},
            "graph": _graph_summary(graph),
            "methodology": {
                "asset_classification": "Primary cryptographic assets separated from supporting artifacts",
                "algorithm_normalization": "Wrapper APIs are resolved into inner algorithms and modes where possible",
                "risk_scoring": "Multi-factor (algorithm, mode, key size, parameter quality, source material, context)",
                "rule_filtering": "Conditional with preconditions and priorities",
                "inference": "Flow-based with explanation tracing",
            },
            "limitations": [
                "Variable-level dataflow is local; interprocedural uses CALLS edges.",
                "Graph context limited to Fraunhofer CPG node properties.",
                "Inference confidence decreases with call chain depth > 3.",
            ],
        },
        "cryptographic_assets": primary_assets,
        "supporting_artifacts": supporting_artifacts,
        "summary": _build_summary(primary_assets, supporting_artifacts, len(ignored)),
    }


def _classify_for_output(
    finding: CryptoFinding,
) -> tuple[CryptoFinding, NormalizedCrypto, AssetClassification]:
    normalized = normalize_finding(finding)
    classification = classify_asset(finding, normalized)
    return finding, normalized, classification


def _asset_from_finding(
    finding: CryptoFinding,
    normalized: NormalizedCrypto,
    classification: AssetClassification,
    rule_engine: RuleEngine,
    risk_engine: RiskEngine,
) -> dict:
    """Convert a finding into a structured CBOM asset with explainability."""
    normalized_finding = finding.model_copy(
        update={
            "algorithm": normalized.algorithm,
            "primitive": normalized.primitive,
            "provider": normalized.provider,
        }
    )
    signals = dict(finding.context.get("signals", {}))
    signals["mode"] = normalized.mode
    signals["padding"] = normalized.padding
    signals["key_size"] = normalized.key_size
    normalized_context = {**finding.context, "signals": signals}

    crypto_metadata = {
        "algorithm": normalized.algorithm,
        "primitive": normalized.primitive,
        "mode": normalized.mode,
        "padding": normalized.padding,
        "provider": normalized.provider or UNKNOWN,
        "key_size": normalized.key_size,
    }

    usage = {
        "operation": normalized.operation,
        "intent": _intent_for(normalized, finding),
    }

    call_chain = finding.context.get("scope", {}).get("call_chain")
    if not call_chain and finding.function:
        call_chain = [finding.function]
    file_value = _normalized_file(finding.file or finding.context.get("scope", {}).get("file"))
    function_value = _normalized_function(
        finding.function or finding.context.get("scope", {}).get("function"),
        file_value,
    )
    context_obj = {
        "file": file_value,
        "function": function_value,
        "line": finding.line,
        "call_chain": [_normalized_function(function, file_value) for function in (call_chain or [])],
    }
    normalized_context = {
        **normalized_context,
        "scope": {
            **normalized_context.get("scope", {}),
            "file": file_value,
            "function": function_value,
            "call_chain": context_obj["call_chain"],
        },
    }

    flow = build_flow(normalized_finding.model_copy(update={"context": normalized_context}), normalized)
    normalized_context = {**normalized_context, "flow": flow}

    control = {
        "execution_path": finding.context.get("control", {}).get("execution_path", "direct"),
        "branch_condition": finding.context.get("control", {}).get("branch_condition"),
        "inside_loop": bool(finding.context.get("control", {}).get("inside_loop", False)),
        "guarded_by_condition": bool(finding.context.get("control", {}).get("guarded_by_condition", False)),
    }

    graph_context_obj = finding.context.get("graph", {})
    graph_context = {
        "call_depth": len(context_obj["call_chain"]),
        "cross_function_flow": bool(
            graph_context_obj.get("call_graph", {}).get("callers")
            or graph_context_obj.get("call_graph", {}).get("callees")
        ),
        "dataflow_steps": len(graph_context_obj.get("incoming_edges", [])) + len(graph_context_obj.get("outgoing_edges", [])),
        "edge_kinds": graph_context_obj.get("edge_kinds", []),
    }

    risk_score = risk_engine.score(
        algorithm=normalized.algorithm,
        primitive=normalized.primitive,
        provider=normalized.provider,
        arguments=finding.arguments,
        api_name=finding.api_name,
        context=normalized_context,
    )

    risk = {
        "level": risk_score.level,
        "confidence": round(risk_score.confidence, 3),
        "tags": risk_score.tags,
        "derivation_summary": risk_score.derivation,
    }

    rule_matches = rule_engine.match_rules(normalized_finding.model_copy(update={"context": normalized_context}))
    rules = [
        {
            "id": match.rule_id,
            "message": match.message,
            "priority": match.priority,
            "actionable": match.is_actionable,
            "explanation": match.explanation,
        }
        for match in rule_matches
    ]

    inference_exps = build_inference_explanations(
        function=function_value,
        api_name=finding.api_name,
        algorithm=normalized.algorithm,
        primitive=normalized.primitive,
        arguments=finding.arguments,
        context=normalized_context,
    )

    inference = {
        "usage_context": explanation_summary(inference_exps["usage_context"]),
        "intent": explanation_summary(inference_exps["intent"]),
        "data_flow": explanation_summary(inference_exps["data_flow"]),
        "derivation_path": explanation_summary(inference_exps["derivation_path"]),
    }

    evidence = {
        "summary": {
            "api_call": finding.api_name,
            "resolved_name": finding.context.get("call", {}).get("resolved_name"),
            "callee": finding.context.get("call", {}).get("callee"),
            "arguments": finding.arguments[:3],  # First 3 only
            "normalization": normalized.evidence,
        },
        "debug": {
            "node_ref": _node_ref(finding),
            "location_ref": f"{finding.file}:{finding.line or UNKNOWN}",
            "raw_node_id": finding.node_id,
            "full_arguments": finding.arguments,
            "argument_signals": signals.get("arguments", []),
            "graph_edges_summary": {
                "incoming_count": len(finding.context.get("graph", {}).get("incoming_edges", [])),
                "outgoing_count": len(finding.context.get("graph", {}).get("outgoing_edges", [])),
                "edge_kinds": finding.context.get("graph", {}).get("edge_kinds", []),
            },
        },
    }

    return {
        "asset_id": _asset_id(finding),
        "asset_class": classification.asset_class,
        "asset_class_reason": classification.reason,
        "crypto_metadata": crypto_metadata,
        "usage": usage,
        "context": context_obj,
        "flow": flow,
        "control": control,
        "graph_context": graph_context,
        "risk": risk,
        "rules": rules,
        "inference": inference,
        "evidence": evidence,
    }


def _get_mode(finding: CryptoFinding, signals: dict[str, Any]) -> str | None:
    """Extract cipher mode if applicable."""
    if finding.primitive not in {
        "symmetric_encryption",
        "authenticated_encryption",
        "asymmetric_encryption",
        "cipher_mode",
    }:
        return None
    return signals.get("mode") or UNKNOWN


def _get_padding(finding: CryptoFinding, signals: dict[str, Any]) -> str | None:
    """Extract padding if applicable."""
    if finding.primitive not in {"symmetric_encryption", "asymmetric_encryption"}:
        return None
    return signals.get("padding") or UNKNOWN


def _get_key_size(finding: CryptoFinding, signals: dict[str, Any]) -> int | str | None:
    """Extract key size if applicable."""
    keyed_primitives = {
        "symmetric_encryption",
        "authenticated_encryption",
        "asymmetric_encryption",
        "key_derivation",
        "message_authentication",
        "asymmetric_key_generation",
    }
    if finding.primitive not in keyed_primitives:
        return None
    return signals.get("key_size") or UNKNOWN


def _operation_for(finding: CryptoFinding) -> str:
    """Map primitive to operation."""
    api = finding.api_name.lower()
    if "decrypt" in api:
        return "decryption"
    if "sign" in api:
        return "signing"

    operation_map = {
        "symmetric_encryption": "encryption",
        "authenticated_encryption": "authenticated_encryption",
        "asymmetric_encryption": "encryption",
        "symmetric_key_generation": "key_generation",
        "asymmetric_key_generation": "key_generation",
        "key_derivation": "key_derivation",
        "hash": "digest",
        "message_authentication": "authentication",
        "random_generation": "random_generation",
        "cipher_mode": "mode_selection",
    }
    return operation_map.get(finding.primitive, finding.primitive)


def _intent_for(normalized: NormalizedCrypto, finding: CryptoFinding | None = None) -> str:
    """Infer intent from algorithm and primitive."""
    algorithm = normalized.algorithm.lower()
    api = (finding.api_name if finding else "").lower()
    context_text = ""
    if finding:
        scope = finding.context.get("scope", {})
        context_text = " ".join(
            [
                str(scope.get("file") or finding.file or ""),
                str(scope.get("function") or finding.function or ""),
                " ".join(scope.get("call_chain", [])),
                api,
            ]
        ).lower()

    if normalized.primitive == "certificate_management" or "certificatebuilder" in api:
        return "build_certificate" if "builder" in api else "manage_certificate_lifecycle"

    if normalized.primitive in {"certificate_request", "certificate_attribute", "certificate_extension"}:
        return "manage_certificate_lifecycle"

    if normalized.primitive == "key_serialization" or "serialization." in api:
        return "key_material_serialization"

    if normalized.primitive in {"asymmetric_key_generation", "symmetric_key_generation"} and any(
        token in context_text for token in ["certificate", "cert", "x509", "csr"]
    ):
        return "create_key_material"

    # Password derivation
    if algorithm in ("pbkdf2", "scrypt", "argon2", "bcrypt"):
        return "derive_password_key"

    # Generic key derivation
    if "pbkdf" in algorithm or "kdf" in algorithm or normalized.primitive == "key_derivation":
        return "derive_key_material"

    # Encryption
    if normalized.primitive in {"symmetric_encryption", "authenticated_encryption", "asymmetric_encryption"}:
        return "encrypt_data"

    # Random
    if normalized.primitive == "random_generation":
        return "create_random_material"

    # Hash
    if normalized.primitive == "hash":
        return "compute_hash_digest"

    # HMAC
    if normalized.primitive == "message_authentication":
        return "verify_integrity"

    if normalized.primitive in {"asymmetric_key_generation", "symmetric_key_generation"}:
        return "create_key_material"

    if normalized.primitive == "certificate_management":
        return "manage_certificate_lifecycle"

    return "general_cryptographic_operation"


def _normalized_file(value: str | None) -> str:
    text = str(value or "").strip()
    return text or "unknown_file"


def _normalized_function(value: str | None, file_value: str) -> str:
    text = str(value or "").strip()
    if text:
        return text
    if file_value != "unknown_file":
        return "module_level"
    return "unknown_function"


def _graph_summary(graph: NormalizedGraph | None) -> dict:
    """Build graph summary section."""
    if graph is None:
        return {"available": False}

    node_counts: dict[str, int] = {}
    edge_counts: dict[str, int] = {}

    for node in graph.nodes:
        node_counts[node.kind] = node_counts.get(node.kind, 0) + 1
    for edge in graph.edges:
        edge_counts[edge.kind] = edge_counts.get(edge.kind, 0) + 1

    return {
        "available": True,
        "backend": graph.backend,
        "root": graph.root,
        "node_count": len(graph.nodes),
        "edge_count": len(graph.edges),
        "node_kinds": node_counts,
        "edge_kinds": edge_counts,
    }


def _build_summary(primary: list[dict], supporting: list[dict], ignored_count: int) -> dict:
    """Build summary statistics."""
    total = len(primary)
    by_risk: dict[str, int] = {}
    by_primitive: dict[str, int] = {}
    by_algorithm: dict[str, int] = {}
    by_provider: dict[str, int] = {}
    by_operation: dict[str, int] = {}

    for asset in primary:
        risk = asset.get("risk", {}).get("level", UNKNOWN)
        metadata = asset.get("crypto_metadata", {})
        operation = asset.get("usage", {}).get("operation", UNKNOWN)
        by_risk[risk] = by_risk.get(risk, 0) + 1
        by_primitive[metadata.get("primitive", UNKNOWN)] = by_primitive.get(metadata.get("primitive", UNKNOWN), 0) + 1
        by_algorithm[metadata.get("algorithm", UNKNOWN)] = by_algorithm.get(metadata.get("algorithm", UNKNOWN), 0) + 1
        provider = metadata.get("provider", UNKNOWN)
        by_provider[provider] = by_provider.get(provider, 0) + 1
        by_operation[operation] = by_operation.get(operation, 0) + 1

    return {
        "total_assets": total,
        "supporting_artifacts": len(supporting),
        "ignored_findings": ignored_count,
        "by_risk": by_risk,
        "by_primitive": by_primitive,
        "by_algorithm": by_algorithm,
        "by_provider": by_provider,
        "by_operation": by_operation,
    }


def _asset_id(finding: CryptoFinding) -> str:
    """Generate stable asset ID."""
    stable = "|".join(
        [
            finding.api_name,
            finding.file,
            str(finding.line),
            finding.function or "",
            finding.node_id,
        ]
    )
    return f"crypto-{sha256(stable.encode('utf-8')).hexdigest()[:16]}"


def _node_ref(finding: CryptoFinding) -> str:
    """Generate node reference."""
    stable = "|".join([finding.file, str(finding.line), finding.function or "", finding.api_name])
    return f"n_{sha256(stable.encode('utf-8')).hexdigest()[:12]}"
