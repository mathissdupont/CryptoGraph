"""Updated crypto matcher using risk_engine for improved risk scoring."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cryptograph.models import CryptoFinding, GraphNode, NormalizedGraph
from cryptograph.risk_engine import RiskEngine
from cryptograph.utils import load_json


def find_crypto_calls(
    graph: NormalizedGraph,
    mappings_path: Path,
    rules_path: Path,
) -> list[CryptoFinding]:
    """Find cryptographic calls using improved risk engine.

    Args:
        graph: Normalized code property graph
        mappings_path: Path to api_mappings.json
        rules_path: Path to rules.json

    Returns:
        List of findings with accurate risk scores
    """
    mappings = load_json(mappings_path)
    rules_config = load_json(rules_path)
    risk_engine = RiskEngine()

    findings: list[CryptoFinding] = []

    for node in graph.nodes:
        if node.kind != "call":
            continue

        api_name = _match_api_name(node, mappings)
        if api_name is None:
            continue

        mapping = mappings[api_name]

        # Create finding with base info
        finding = CryptoFinding(
            api_name=api_name,
            node_id=node.id,
            file=node.file,
            line=node.line,
            function=node.function,
            algorithm=mapping["algorithm"],
            primitive=mapping["primitive"],
            provider=mapping.get("provider"),
            arguments=list(node.properties.get("arguments", [])),
            risk="info",  # Will be updated by risk engine
        )

        # Store context from node and mapping
        finding.context = {
            "call": {
                "resolved_name": node.properties.get("resolved_name"),
                "callee": node.properties.get("callee"),
            },
            "signals": {
                "mode": _extract_mode(finding, node),
                "padding": _extract_padding(finding, node),
                "key_size": _extract_key_size(finding, node),
                "arguments": _extract_argument_signals(node),
                "sources": _classify_sources(node, finding),
                "sink": _classify_sink(node, finding),
            },
            "control": _extract_control_flow(node),
            "scope": {
                "call_chain": [finding.function] if finding.function else [],
            },
            "graph": _extract_graph_context(graph, node),
        }

        # Compute risk score using new engine
        risk_score = risk_engine.score(
            algorithm=finding.algorithm,
            primitive=finding.primitive,
            provider=finding.provider,
            arguments=finding.arguments,
            api_name=finding.api_name,
            context=finding.context,
        )

        # Update finding with computed risk
        finding.risk = risk_score.level
        finding.context["risk_derivation"] = risk_score.derivation
        finding.context["risk_tags"] = risk_score.tags
        finding.context["risk_confidence"] = risk_score.confidence

        # Collect rule IDs (without applying global risk escalation)
        # Rules now provide information only, not risk level changes
        for rule in rules_config.get("rules", []):
            if _old_style_rule_matches(finding, node, rule.get("match", {})):
                finding.rule_ids.append(rule["id"])
                finding.rule_messages.append(rule.get("message", ""))

        findings.append(finding)

    return findings


def _match_api_name(node: GraphNode, mappings: dict[str, Any]) -> str | None:
    """Find API name in the mappings."""
    candidates = [
        node.name or "",
        str(node.properties.get("resolved_name", "")),
        str(node.properties.get("callee", "")),
    ]
    for candidate in candidates:
        for api_name in mappings:
            if candidate == api_name or candidate.endswith(f".{api_name}"):
                return api_name
    return None


def _extract_mode(finding: CryptoFinding, node: GraphNode) -> str | None:
    """Extract cipher mode from arguments if applicable."""
    if finding.primitive not in {
        "symmetric_encryption",
        "authenticated_encryption",
        "asymmetric_encryption",
        "cipher_mode",
    }:
        return None

    # Look for mode in arguments
    args = node.properties.get("arguments", [])
    for arg in args:
        arg_str = str(arg).lower()
        if "ecb" in arg_str or "modes.ecb" in arg_str:
            return "ECB"
        if "cbc" in arg_str or "modes.cbc" in arg_str:
            return "CBC"
        if "ctr" in arg_str or "modes.ctr" in arg_str:
            return "CTR"
        if "gcm" in arg_str or "modes.gcm" in arg_str:
            return "GCM"
        if "ofb" in arg_str or "modes.ofb" in arg_str:
            return "OFB"
        if "cfb" in arg_str or "modes.cfb" in arg_str:
            return "CFB"

    # Check API name pattern
    api = finding.api_name.lower()
    if "ecb" in api:
        return "ECB"
    if "cbc" in api:
        return "CBC"
    if "ctr" in api:
        return "CTR"
    if "gcm" in api:
        return "GCM"

    return None


def _extract_padding(finding: CryptoFinding, node: GraphNode) -> str | None:
    """Extract padding scheme from arguments."""
    if finding.primitive not in {"symmetric_encryption", "asymmetric_encryption"}:
        return None

    args = node.properties.get("arguments", [])
    for arg in args:
        arg_str = str(arg).lower()
        if "pkcs" in arg_str:
            if "pkcs1v15" in arg_str or "pkcs1" in arg_str:
                return "PKCS1v15"
            if "pkcs7" in arg_str:
                return "PKCS7"
            if "oaep" in arg_str:
                return "OAEP"

    return None


def _extract_key_size(finding: CryptoFinding, node: GraphNode) -> int | None:
    """Extract key size from arguments."""
    if finding.primitive not in {
        "symmetric_encryption",
        "authenticated_encryption",
        "asymmetric_encryption",
        "key_derivation",
        "message_authentication",
        "asymmetric_key_generation",
    }:
        return None

    args = node.properties.get("arguments", [])
    for arg in args:
        try:
            # Look for numeric arguments that might be key sizes
            val = int(arg)
            if 128 <= val <= 4096:  # Reasonable key size range
                return val
        except ValueError:
            pass

    return None


def _extract_argument_signals(node: GraphNode) -> list[dict]:
    """Extract information from function arguments."""
    signals = []
    args = node.properties.get("arguments", [])
    for index, arg in enumerate(args):
        signals.append({
            "index": index,
            "value": str(arg),
            "role": f"arg_{index}",
            "is_literal": isinstance(arg, (str, int, float)),
        })
    return signals


def _classify_sources(node: GraphNode, finding: CryptoFinding) -> list[dict]:
    """Classify data sources feeding into this operation."""
    sources = []

    # Check for hardcoded literals
    literals = node.properties.get("literal_arguments", [])
    if literals:
        sources.append({
            "classification": "hardcoded_constant",
            "origin": "literal",
            "values": literals,
        })

    # Check if it's from os.urandom or secrets
    if "urandom" in str(finding.api_name).lower() or "secrets" in str(finding.api_name).lower():
        sources.append({
            "classification": "generated_random",
            "origin": "csprng",
        })

    # For key derivation, source is usually password
    if finding.primitive == "key_derivation":
        sources.append({
            "classification": "user_input",
            "origin": "function_parameter",
            "hint": "password/passphrase",
        })

    return sources


def _classify_sink(node: GraphNode, finding: CryptoFinding) -> dict:
    """Classify where this operation's output goes."""
    sink_id = None

    if finding.primitive in {"symmetric_encryption", "asymmetric_encryption", "authenticated_encryption"}:
        sink_id = "encryption_output"
    elif finding.primitive == "key_derivation":
        sink_id = "derived_key"
    elif finding.primitive == "hash":
        sink_id = "hash_digest"

    return {
        "sink_id": sink_id,
        "classification": "cryptographic_output" if sink_id else "unknown",
    }


def _extract_control_flow(node: GraphNode) -> dict:
    """Extract control flow information."""
    return {
        "execution_path": "direct",
        "inside_loop": node.properties.get("inside_loop", False),
        "guarded_by_condition": node.properties.get("guarded_by_condition", False),
        "branch_condition": node.properties.get("branch_condition"),
    }


def _extract_graph_context(graph: NormalizedGraph, node: GraphNode) -> dict:
    """Extract relevant graph context."""
    # Find related nodes in graph
    incoming_edges = [e for e in graph.edges if e.target == node.id]
    outgoing_edges = [e for e in graph.edges if e.source == node.id]

    edge_kinds = set()
    for edge in incoming_edges + outgoing_edges:
        edge_kinds.add(edge.kind)

    return {
        "incoming_edges": [{"kind": e.kind, "source": e.source} for e in incoming_edges[:3]],
        "outgoing_edges": [{"kind": e.kind, "target": e.target} for e in outgoing_edges[:3]],
        "edge_kinds": list(edge_kinds),
        "call_graph": {
            "callers": [],
            "callees": [],
        },
    }


def _old_style_rule_matches(
    finding: CryptoFinding,
    node: GraphNode,
    match: dict[str, Any],
) -> bool:
    """Check if rule matches using compatibility with old rule format.

    This is kept for backward compatibility with existing rules.json.
    The new rule_engine.py provides the proper conditional matching.
    """
    if not match:
        return False

    # Single-value matches
    if "api_name" in match and finding.api_name != match["api_name"]:
        return False

    # List matches
    if "api_name_in" in match and finding.api_name not in match["api_name_in"]:
        return False

    if "algorithm_in" in match and finding.algorithm not in match["algorithm_in"]:
        return False

    # Argument-based matches
    if "argument_contains" in match:
        needle = match["argument_contains"]
        if not any(needle in arg for arg in finding.arguments):
            return False

    # String literal detection
    if "has_string_literal_argument" in match and match["has_string_literal_argument"]:
        if node and node.properties.get("literal_arguments"):
            if not any(isinstance(val, str) for val in node.properties.get("literal_arguments", [])):
                return False
        else:
            return False

    # Numeric argument matching
    if "numeric_argument_less_than" in match:
        threshold = int(match["numeric_argument_less_than"])
        if not any(
            _parse_int(argument) is not None and _parse_int(argument) < threshold
            for argument in finding.arguments
        ):
            return False

    return True


def _parse_int(value: str) -> int | None:
    """Try to parse integer from string."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return None
