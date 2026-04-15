from __future__ import annotations

from pathlib import Path
from typing import Any

from cryptograph.models import CryptoFinding, GraphNode, NormalizedGraph
from cryptograph.utils import load_json


RISK_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def find_crypto_calls(
    graph: NormalizedGraph,
    mappings_path: Path,
    rules_path: Path,
) -> list[CryptoFinding]:
    mappings = load_json(mappings_path)
    rules_config = load_json(rules_path)
    findings: list[CryptoFinding] = []
    for node in graph.nodes:
        if node.kind != "call":
            continue
        api_name = _match_api_name(node, mappings)
        if api_name is None:
            continue
        mapping = mappings[api_name]
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
            risk=rules_config.get("default_risk", "info"),
        )
        _apply_rules(finding, node, rules_config.get("rules", []))
        findings.append(finding)
    return findings


def _match_api_name(node: GraphNode, mappings: dict[str, Any]) -> str | None:
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


def _apply_rules(finding: CryptoFinding, node: GraphNode, rules: list[dict[str, Any]]) -> None:
    for rule in rules:
        match = rule.get("match", {})
        if not _rule_matches(finding, node, match):
            continue
        finding.rule_ids.append(rule["id"])
        finding.rule_messages.append(rule.get("message", ""))
        finding.risk = _max_risk(finding.risk, rule.get("risk", "info"))


def _rule_matches(finding: CryptoFinding, node: GraphNode, match: dict[str, Any]) -> bool:
    if "api_name" in match and finding.api_name != match["api_name"]:
        return False
    if "api_name_in" in match and finding.api_name not in match["api_name_in"]:
        return False
    if "algorithm_in" in match and finding.algorithm not in match["algorithm_in"]:
        return False
    if "primitive_in" in match and finding.primitive not in match["primitive_in"]:
        return False
    if "provider_in" in match and finding.provider not in match["provider_in"]:
        return False
    if match.get("has_string_literal_argument") is True:
        literals = node.properties.get("literal_arguments", [])
        if not any(isinstance(value, str) for value in literals):
            return False
    if "argument_contains" in match:
        needle = match["argument_contains"]
        if not any(needle in arg for arg in finding.arguments):
            return False
    if "argument_contains_any" in match:
        needles = match["argument_contains_any"]
        if not any(needle in arg for needle in needles for arg in finding.arguments):
            return False
    if "numeric_argument_less_than" in match:
        threshold = int(match["numeric_argument_less_than"])
        if not any(_parse_int(argument) is not None and _parse_int(argument) < threshold for argument in finding.arguments):
            return False
    return True


def _max_risk(left: str, right: str) -> str:
    return right if RISK_ORDER.get(right, 0) > RISK_ORDER.get(left, 0) else left


def _parse_int(value: str) -> int | None:
    try:
        return int(value.replace("_", "").strip())
    except ValueError:
        return None
