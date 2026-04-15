from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from cryptograph.models import CryptoFinding, NormalizedGraph

UNKNOWN = "unknown"

ENCRYPTION_PRIMITIVES = {
    "symmetric_encryption",
    "authenticated_encryption",
    "asymmetric_encryption",
}
KEYED_PRIMITIVES = ENCRYPTION_PRIMITIVES | {"key_derivation", "message_authentication"}
DATA_PRIMITIVES = ENCRYPTION_PRIMITIVES | {"hash", "key_derivation", "message_authentication"}


def build_cbom(
    findings: list[CryptoFinding],
    source: str,
    backend: str,
    graph: NormalizedGraph | None = None,
    run_id: str | None = None,
) -> dict:
    return {
        "cbom_format": "cryptograph-custom",
        "spec_version": "0.2",
        "metadata": {
            "tool": "CryptoGraph",
            "generated_at": datetime.now(UTC).isoformat(),
            "source": source,
            "backend": backend,
            "run_id": run_id,
            "source_language": "python",
            "schema_note": "CryptoGraph custom CBOM format, not CycloneDX CBOM.",
        },
        "analysis": {
            "scope": {"input": source, "language": "python", "backend": backend},
            "graph": _graph_summary(graph),
            "limitations": [
                "Variable-level dataflow is currently local and graph-assisted.",
                "Interprocedural propagation uses normalized CALLS edges and function signatures where available.",
                "Unknown values are emitted as 'unknown' when applicable but unresolved; null means not applicable.",
            ],
        },
        "cryptographic_assets": [_asset_from_finding(finding) for finding in findings],
        "summary": {
            "total_assets": len(findings),
            "by_risk": _count_by(findings, "risk"),
            "by_primitive": _count_by(findings, "primitive"),
            "by_algorithm": _count_by(findings, "algorithm"),
            "by_provider": _count_by(findings, "provider"),
            "by_operation": _count_operations(findings),
        },
    }


def _asset_from_finding(finding: CryptoFinding) -> dict:
    signals = finding.context.get("signals", {})
    graph_context = finding.context.get("graph", {})
    dataflow = finding.context.get("dataflow", {})
    risk_tags = _risk_tags_for(finding)
    confidence = _confidence_score(finding, graph_context, dataflow)

    return {
        "asset_id": _asset_id(finding),
        "crypto_metadata": {
            "algorithm": finding.algorithm,
            "primitive": finding.primitive,
            "mode": _mode_for(finding),
            "padding": _padding_for(finding),
            "provider": finding.provider or UNKNOWN,
            "key_size": _key_size_for(finding),
        },
        "usage": {
            "operation": _operation_for(finding),
            "intent": _intent_for(finding),
        },
        "context": {
            "file": finding.file,
            "function": finding.function,
            "line": finding.line,
            "call_chain": _call_chain_for(finding),
            "usage_context": _usage_context_for(finding),
        },
        "flow": {
            "key_source": _flow_source(finding, "key"),
            "data_source": _flow_source(finding, "data"),
            "iv_source": _flow_source(finding, "iv"),
            "salt_source": _flow_source(finding, "salt"),
            "randomness_source": _flow_source(finding, "randomness"),
            "source_to_sink": _source_to_sink_for(signals.get("sources", []), signals.get("sink")),
            "variable_flows": dataflow.get("sources_reaching_sink", []),
        },
        "control": {
            "execution_path": _execution_path_for(graph_context),
            "branch_condition": finding.context.get("control", {}).get("branch_condition"),
            "inside_loop": bool(finding.context.get("control", {}).get("inside_loop", False)),
            "guarded_by_condition": bool(finding.context.get("control", {}).get("guarded_by_condition", False)),
            "call_graph": graph_context.get("call_graph", {}),
        },
        "risk": {
            "tags": risk_tags,
            "level": finding.risk,
            "confidence": confidence,
            "confidence_reasons": _confidence_reasons(finding, graph_context, dataflow),
        },
        "evidence": {
            "api_call": finding.api_name,
            "resolved_name": finding.context.get("call", {}).get("resolved_name"),
            "callee": finding.context.get("call", {}).get("callee"),
            "mode_arg": _mode_argument(finding),
            "arguments": finding.arguments,
            "argument_signals": signals.get("arguments", []),
            "node_ref": _node_ref(finding),
            "location_ref": _location_ref(finding),
            "raw_node_id": finding.node_id,
            "graph_edges": graph_context.get("incoming_edges", []) + graph_context.get("outgoing_edges", []),
            "graph_edge_kinds": graph_context.get("edge_kinds", []),
            "rules": [
                {"id": rule_id, "message": message}
                for rule_id, message in zip(finding.rule_ids, finding.rule_messages, strict=False)
            ],
        },
    }


def _graph_summary(graph: NormalizedGraph | None) -> dict:
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


def _count_by(findings: list[CryptoFinding], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        value = str(getattr(finding, field) or UNKNOWN)
        counts[value] = counts.get(value, 0) + 1
    return counts


def _count_operations(findings: list[CryptoFinding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        operation = _operation_for(finding)
        counts[operation] = counts.get(operation, 0) + 1
    return counts


def _asset_id(finding: CryptoFinding) -> str:
    stable = "|".join([finding.api_name, finding.file, str(finding.line), finding.function or "", finding.node_id])
    return f"crypto-{sha256(stable.encode('utf-8')).hexdigest()[:16]}"


def _node_ref(finding: CryptoFinding) -> str:
    stable = "|".join([finding.file, str(finding.line), finding.function or "", finding.api_name])
    return f"n_{sha256(stable.encode('utf-8')).hexdigest()[:12]}"


def _location_ref(finding: CryptoFinding) -> str:
    return f"{finding.file}:{finding.line or UNKNOWN}"


def _operation_for(finding: CryptoFinding) -> str:
    api = finding.api_name.lower()
    if "decrypt" in api:
        return "decryption"
    if "sign" in api:
        return "signing"
    if finding.primitive in {"symmetric_encryption", "authenticated_encryption", "asymmetric_encryption"}:
        return "encryption"
    if finding.primitive in {"symmetric_key_generation", "asymmetric_key_generation"}:
        return "key_generation"
    if finding.primitive == "key_derivation":
        return "key_derivation"
    if finding.primitive == "hash":
        return "digest"
    if finding.primitive == "message_authentication":
        return "authentication"
    if finding.primitive == "random_generation":
        return "random_generation"
    if finding.primitive == "cipher_mode":
        return "mode_selection"
    return finding.primitive


def _mode_for(finding: CryptoFinding) -> str | None:
    if finding.primitive not in ENCRYPTION_PRIMITIVES and finding.primitive != "cipher_mode":
        return None
    return finding.context.get("signals", {}).get("mode") or UNKNOWN


def _padding_for(finding: CryptoFinding) -> str | None:
    if finding.primitive not in ENCRYPTION_PRIMITIVES:
        return None
    return finding.context.get("signals", {}).get("padding") or UNKNOWN


def _key_size_for(finding: CryptoFinding) -> int | str | None:
    if finding.primitive not in KEYED_PRIMITIVES and "key_generation" not in finding.primitive:
        return None
    return finding.context.get("signals", {}).get("key_size") or UNKNOWN


def _mode_argument(finding: CryptoFinding) -> str | None:
    return next((argument for argument in finding.arguments if "MODE_" in argument or "modes." in argument), None)


def _call_chain_for(finding: CryptoFinding) -> list[str]:
    call_chain = finding.context.get("scope", {}).get("call_chain")
    if call_chain:
        return call_chain
    return [finding.function] if finding.function else []


def _flow_source(finding: CryptoFinding, role: str) -> str | None:
    if not _flow_role_applies(finding, role):
        return None
    argument_signals = finding.context.get("signals", {}).get("arguments", [])
    role_matches = [signal for signal in argument_signals if signal.get("role") == role]
    classifications = finding.context.get("signals", {}).get("sources", [])

    if role == "key" and any(item.get("classification") == "key_material" for item in classifications):
        return "function_parameter" if _has_origin(role_matches, "function_parameter") else "classified_key_material"
    if role == "data" and any(item.get("classification") == "user_input" for item in classifications):
        return "function_parameter" if _has_origin(role_matches, "function_parameter") else "classified_user_input"
    if role == "randomness" and any(item.get("classification") == "generated_random" for item in classifications):
        return "generated_random"
    if _has_origin(role_matches, "function_parameter"):
        return "function_parameter"
    if _has_origin(role_matches, "assignment"):
        return "local_assignment"
    return UNKNOWN


def _flow_role_applies(finding: CryptoFinding, role: str) -> bool:
    if role == "key":
        return finding.primitive in KEYED_PRIMITIVES or "key_generation" in finding.primitive
    if role == "data":
        return finding.primitive in DATA_PRIMITIVES
    if role == "iv":
        return finding.primitive in {"symmetric_encryption", "authenticated_encryption"}
    if role == "salt":
        return finding.primitive == "key_derivation"
    if role == "randomness":
        return finding.primitive in {"random_generation", "symmetric_key_generation", "asymmetric_key_generation", "key_derivation"}
    return False


def _has_origin(argument_signals: list[dict[str, Any]], origin_kind: str) -> bool:
    return any((signal.get("assignment_origin") or {}).get("kind") == origin_kind for signal in argument_signals)


def _source_to_sink_for(sources: list[dict], sink: dict | None) -> dict:
    grouped: dict[str, list[str]] = {}
    for source in sources:
        classification = source.get("classification")
        argument = source.get("argument")
        if classification and argument:
            grouped.setdefault(classification, []).append(argument)
    return {"sources": grouped, "sink": sink, "inferred": bool(grouped and sink)}


def _execution_path_for(graph_context: dict) -> str:
    edge_kinds = set(graph_context.get("edge_kinds", []))
    if any(kind.startswith("EOG") for kind in edge_kinds):
        return "graph_eog"
    if "AST_FUNCTION" in edge_kinds:
        return "direct"
    return UNKNOWN


def _usage_context_for(finding: CryptoFinding) -> str:
    text = f"{finding.file} {finding.function or ''} {' '.join(_call_chain_for(finding))}".lower()
    if any(token in text for token in ["auth", "login", "token", "password"]):
        return "authentication_flow"
    if any(token in text for token in ["rsa", "recipient"]):
        return "key_exchange_or_recipient_encryption"
    return "general_crypto_usage"


def _intent_for(finding: CryptoFinding) -> str:
    operation = _operation_for(finding)
    if operation in {"encryption", "decryption"}:
        return "protect_data_confidentiality"
    if operation == "key_derivation":
        return "derive_key_material"
    if operation == "digest":
        return "produce_data_digest"
    if operation == "authentication":
        return "protect_message_integrity"
    if operation == "key_generation":
        return "create_key_material"
    if operation == "random_generation":
        return "create_random_material"
    if operation == "signing":
        return "prove_data_origin_or_integrity"
    return "cryptographic_operation"


def _risk_tags_for(finding: CryptoFinding) -> list[str]:
    tags_by_rule = {
        "AES_ECB_MODE": "insecure_mode",
        "ECB_MODE_OBJECT": "insecure_mode",
        "LEGACY_BLOCK_CIPHER": "legacy_algorithm",
        "DEPRECATED_HASH": "deprecated_algorithm",
        "RSA_SMALL_KEY": "small_key_size",
        "PBKDF2_LOW_ITERATIONS": "weak_kdf_parameters",
        "WEAK_PRNG": "weak_random_source",
        "HARDCODED_CRYPTO_LITERAL": "possible_hardcoded_secret",
        "CBC_REQUIRES_AUTH_REVIEW": "requires_authentication_review",
    }
    tags = [tags_by_rule[rule_id] for rule_id in finding.rule_ids if rule_id in tags_by_rule]
    if finding.risk in {"high", "critical"} and not tags:
        tags.append("high_risk_crypto_usage")
    return tags


def _confidence_score(finding: CryptoFinding, graph_context: dict, dataflow: dict) -> float:
    score = 0.15
    if finding.api_name:
        score += 0.15
    if finding.file and finding.line:
        score += 0.10
    if finding.context.get("call", {}).get("callee"):
        score += 0.12
    if graph_context.get("edge_kinds"):
        score += 0.12
    if graph_context.get("call_graph", {}).get("call_chain"):
        score += 0.10
    if finding.context.get("signals", {}).get("sources"):
        score += 0.10
    if dataflow.get("available"):
        score += 0.16
    if finding.rule_ids:
        score += 0.10
    return round(min(score, 1.0), 2)


def _confidence_reasons(finding: CryptoFinding, graph_context: dict, dataflow: dict) -> list[str]:
    reasons = []
    if finding.api_name:
        reasons.append("api_mapping_match")
    if finding.file and finding.line:
        reasons.append("source_location_available")
    if finding.context.get("call", {}).get("callee"):
        reasons.append("fraunhofer_callee_available")
    if graph_context.get("edge_kinds"):
        reasons.append("graph_context_available")
    if graph_context.get("call_graph", {}).get("call_chain"):
        reasons.append("call_chain_available")
    if finding.context.get("signals", {}).get("sources"):
        reasons.append("source_sink_classification_available")
    if dataflow.get("available"):
        reasons.append("dataflow_or_assignment_origin_available")
    if finding.rule_ids:
        reasons.append("risk_rule_matched")
    return reasons
