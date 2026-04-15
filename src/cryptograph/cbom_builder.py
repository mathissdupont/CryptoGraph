from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256

from cryptograph.models import CryptoFinding, NormalizedGraph


def build_cbom(
    findings: list[CryptoFinding],
    source: str,
    backend: str,
    graph: NormalizedGraph | None = None,
    run_id: str | None = None,
) -> dict:
    return {
        "cbom_format": "cryptograph-custom",
        "spec_version": "0.1",
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
            "scope": {
                "input": source,
                "language": "python",
                "backend": backend,
            },
            "graph": _graph_summary(graph),
            "limitations": [
                "MVP normalizes selected CPG node and edge types.",
                "Usage intent is inferred from API, file/function names and local graph context.",
                "Full interprocedural dataflow is not yet complete.",
            ],
        },
        "cryptographic_assets": [_asset_from_finding(finding) for finding in findings],
        "summary": {
            "total_assets": len(findings),
            "by_risk": _count_by(findings, "risk"),
            "by_primitive": _count_by(findings, "primitive"),
            "by_algorithm": _count_by(findings, "algorithm"),
            "by_provider": _count_by(findings, "provider"),
        },
    }


def _asset_from_finding(finding: CryptoFinding) -> dict:
    signals = finding.context.get("signals", {})
    mode = signals.get("mode")
    mode_arg = _first_argument_containing(finding.arguments, "MODE_")
    graph_context = finding.context.get("graph", {})
    source_summary = _source_summary(signals.get("sources", []))

    return {
        "asset_id": _asset_id(finding),
        "crypto_metadata": {
            "algorithm": finding.algorithm,
            "primitive": finding.primitive,
            "usage": _usage_for(finding),
            "mode": mode,
            "provider": finding.provider,
        },
        "code_context": {
            "file": finding.file,
            "function": finding.function,
            "line": finding.line,
            "call_chain": _call_chain_for(finding),
            "scope_kind": graph_context.get("backend_node_kind", "call"),
        },
        "flow": {
            "key_source": _key_source_for(finding),
            "data_source": _data_source_for(finding),
            "source_classifications": signals.get("sources", []),
            "sink_classification": signals.get("sink"),
            "source_to_sink": _source_to_sink_for(source_summary, signals.get("sink")),
            "dfg_edges": _edges_with_prefix(graph_context, "DFG"),
            "argument_sources": _argument_sources(graph_context),
        },
        "control": {
            "execution_path": _execution_path_for(graph_context),
            "eog_edges": _edges_with_prefix(graph_context, "EOG"),
            "ast_parent": _first_edge_neighbor(graph_context, "AST_FUNCTION", direction="incoming"),
            "call_graph": graph_context.get("call_graph", {}),
        },
        "inference": {
            "usage_context": _usage_context_for(finding),
            "intent": _intent_for(finding),
            "risk_tags": _risk_tags_for(finding),
            "risk_level": finding.risk,
            "confidence": _confidence_for(finding, graph_context),
            "confidence_reasons": _confidence_reasons(finding, graph_context),
        },
        "evidence": {
            "api_call": finding.api_name,
            "resolved_name": finding.context.get("call", {}).get("resolved_name"),
            "callee": finding.context.get("call", {}).get("callee"),
            "mode_arg": mode_arg,
            "arguments": finding.arguments,
            "node_id": finding.node_id,
            "graph_edges": graph_context.get("incoming_edges", []) + graph_context.get("outgoing_edges", []),
            "graph_edge_kinds": graph_context.get("edge_kinds", []),
            "rules": [
                {"id": rule_id, "message": message}
                for rule_id, message in zip(finding.rule_ids, finding.rule_messages, strict=False)
            ],
        },
    }


def _count_by(findings: list[CryptoFinding], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        value = str(getattr(finding, field) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return counts


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


def _first_argument_containing(arguments: list[str], needle: str) -> str | None:
    return next((argument for argument in arguments if needle in argument), None)


def _asset_id(finding: CryptoFinding) -> str:
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


def _usage_for(finding: CryptoFinding) -> str:
    usage_by_primitive = {
        "symmetric_encryption": "encryption",
        "authenticated_encryption": "encryption",
        "asymmetric_encryption": "encryption",
        "asymmetric_key_generation": "key_generation",
        "symmetric_key_generation": "key_generation",
        "key_derivation": "key_derivation",
        "hash": "digest",
        "message_authentication": "authentication",
        "random_generation": "random_generation",
    }
    return usage_by_primitive.get(finding.primitive, finding.primitive)


def _call_chain_for(finding: CryptoFinding) -> list[str]:
    call_chain = finding.context.get("scope", {}).get("call_chain")
    if call_chain:
        return call_chain
    if finding.function:
        return [finding.function]
    return []


def _key_source_for(finding: CryptoFinding) -> str | None:
    classifications = finding.context.get("signals", {}).get("sources", [])
    if any(item.get("classification") == "key_material" for item in classifications):
        return "classified_key_material"
    if any(item.get("classification") == "generated_random" for item in classifications):
        return "generated_random"
    joined = " ".join(finding.arguments).lower()
    if "generate_key" in finding.api_name or finding.primitive.endswith("key_generation"):
        return "generated_in_function"
    if "token_bytes" in finding.api_name or "urandom" in finding.api_name:
        return "csprng"
    if "key" in joined or "password" in joined:
        return "function_parameter"
    return None


def _data_source_for(finding: CryptoFinding) -> str | None:
    classifications = finding.context.get("signals", {}).get("sources", [])
    if any(item.get("classification") == "user_input" for item in classifications):
        return "classified_user_input"
    joined = " ".join(finding.arguments).lower()
    if any(name in joined for name in ["data", "payload", "message", "token", "password", "note"]):
        return "function_parameter"
    return None


def _usage_context_for(finding: CryptoFinding) -> str | None:
    text = f"{finding.file} {finding.function or ''}".lower()
    if any(token in text for token in ["auth", "login", "token", "password"]):
        return "authentication_flow"
    if any(token in text for token in ["rsa", "recipient"]):
        return "key_exchange_or_recipient_encryption"
    return "general_crypto_usage"


def _intent_for(finding: CryptoFinding) -> str:
    usage = _usage_for(finding)
    if usage == "encryption":
        return "protect_data_confidentiality"
    if usage == "key_derivation":
        return "derive_key_material"
    if usage == "digest":
        return "produce_data_digest"
    if usage == "authentication":
        return "protect_message_integrity"
    if usage == "key_generation":
        return "create_key_material"
    if usage == "random_generation":
        return "create_random_material"
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


def _edges_with_prefix(graph_context: dict, prefix: str) -> list[dict]:
    edges = graph_context.get("incoming_edges", []) + graph_context.get("outgoing_edges", [])
    return [edge for edge in edges if str(edge.get("kind", "")).startswith(prefix)]


def _argument_sources(graph_context: dict) -> list[dict]:
    edges = graph_context.get("outgoing_edges", [])
    return [edge for edge in edges if str(edge.get("kind", "")).startswith("AST_ARGUMENT")]


def _execution_path_for(graph_context: dict) -> str:
    edge_kinds = set(graph_context.get("edge_kinds", []))
    if any(kind.startswith("EOG") for kind in edge_kinds):
        return "graph_eog"
    if "AST_FUNCTION" in edge_kinds:
        return "function_scope"
    return "direct"


def _first_edge_neighbor(graph_context: dict, kind: str, direction: str) -> dict | None:
    edges = graph_context.get("incoming_edges", []) + graph_context.get("outgoing_edges", [])
    for edge in edges:
        if edge.get("kind") == kind and edge.get("direction") == direction:
            return {
                "node_id": edge.get("neighbor_id"),
                "kind": edge.get("neighbor_kind"),
                "name": edge.get("neighbor_name"),
                "code": edge.get("neighbor_code"),
            }
    return None


def _confidence_for(finding: CryptoFinding, graph_context: dict) -> str:
    score = 0
    if finding.api_name:
        score += 1
    if finding.file and finding.line:
        score += 1
    if graph_context.get("edge_kinds"):
        score += 1
    if finding.rule_ids:
        score += 1
    if finding.context.get("call", {}).get("callee"):
        score += 1
    if finding.context.get("signals", {}).get("sources"):
        score += 1
    if graph_context.get("call_graph", {}).get("call_chain"):
        score += 1
    if score >= 5:
        return "high"
    if score >= 2:
        return "medium"
    return "low"


def _confidence_reasons(finding: CryptoFinding, graph_context: dict) -> list[str]:
    reasons = []
    if finding.api_name:
        reasons.append("api_mapping_match")
    if finding.file and finding.line:
        reasons.append("source_location_available")
    if graph_context.get("edge_kinds"):
        reasons.append("graph_context_available")
    if finding.rule_ids:
        reasons.append("risk_rule_matched")
    if finding.context.get("call", {}).get("callee"):
        reasons.append("fraunhofer_callee_available")
    if finding.context.get("signals", {}).get("sources"):
        reasons.append("source_sink_classification_available")
    if graph_context.get("call_graph", {}).get("call_chain"):
        reasons.append("call_chain_available")
    return reasons


def _source_summary(classifications: list[dict]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for item in classifications:
        classification = item.get("classification")
        argument = item.get("argument")
        if classification and argument:
            result.setdefault(classification, []).append(argument)
    return result


def _source_to_sink_for(source_summary: dict[str, list[str]], sink: dict | None) -> dict:
    return {
        "sources": source_summary,
        "sink": sink,
        "inferred": bool(source_summary and sink),
    }
