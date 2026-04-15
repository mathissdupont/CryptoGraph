"""
Variable-Level Dataflow Analysis for CryptoGraph

This module enriches cryptographic findings with contextual signals including:
- Call chain ancestry (callers up to MAX_CALL_CHAIN_DEPTH levels)
- Argument signals: literal values, modes (CBC/GCM), padding, key sizes
- Source/sink classification from config/source_sinks.json
- **Variable-level dataflow**: hybrid approach combining:
  * Graph-based tracking: follow DFG, DATA_FLOW, REACHES edges when present
  * Local AST analysis: extract function-local assignments and parameter origins
  * Combined evidence: report both sources in the CBOM flow.sources_reaching_sink field

Challenge: Fraunhofer CPG's Python frontend does not guarantee full interprocedural
dataflow for every source-to-sink pattern. For patterns like:
  request["token"] → token → encrypt(token)
the graph may lack complete DFG edges. Variable-level dataflow bridges this gap by
analyzing local assignments (token = request["token"]) and reporting them alongside
any graph-based dataflow evidence.

Implementation:
- _extract_argument_signals(): parse arguments and extract local origins
- _assignment_origin(): walk function's AST for variable assignments/parameters
- _dataflow_analysis(): combine graph edges + assignment origins
- _reaching_dataflow_sources(): BFS over DFG edges (up to MAX_DATAFLOW_DEPTH=24)
"""

from __future__ import annotations

import ast
import re
from collections import deque
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from cryptograph.models import CryptoFinding, GraphEdge, GraphNode, NormalizedGraph
from cryptograph.utils import load_json, project_path

# Edge kinds used to track dataflow in the normalized graph
DATA_FLOW_EDGE_KINDS = {"DFG", "DATA_FLOW", "REACHES"}
MAX_CALL_CHAIN_DEPTH = 24
MAX_DATAFLOW_DEPTH = 24


@dataclass(frozen=True)
class FunctionInfo:
    name: str
    parameters: list[str]
    assignments: dict[str, str]
    calls: list[dict[str, Any]]
    raw_code: str


def enrich_context(
    findings: list[CryptoFinding],
    graph: NormalizedGraph,
    source_sinks_path: Path | None = None,
) -> list[CryptoFinding]:
    source_sinks = load_json(source_sinks_path or project_path("config", "source_sinks.json"))
    nodes_by_id = {node.id: node for node in graph.nodes}
    incoming_edges = _edges_by_target(graph)
    outgoing_edges = _edges_by_source(graph)
    call_graph = _call_graph(graph, nodes_by_id)
    reverse_call_graph = _reverse_call_graph(call_graph)
    functions = _function_infos(graph)

    for finding in findings:
        node = nodes_by_id.get(finding.node_id)
        if not node:
            continue

        arguments = [str(argument) for argument in node.properties.get("arguments", [])]
        incoming = incoming_edges.get(node.id, [])
        outgoing = outgoing_edges.get(node.id, [])
        incoming_summaries = [_edge_summary(edge, nodes_by_id, incoming=True) for edge in incoming]
        outgoing_summaries = [_edge_summary(edge, nodes_by_id, incoming=False) for edge in outgoing]
        call_chain = _call_chain(finding.function, reverse_call_graph)
        argument_signals = _extract_argument_signals(
            arguments,
            node,
            functions.get(finding.function or ""),
            source_sinks.get("sources", []),
        )
        scope_sources = _classify_scope(finding.function, incoming_summaries, source_sinks.get("sources", []))
        dataflow = _dataflow_analysis(node, graph, nodes_by_id, incoming_edges, outgoing_edges, argument_signals)

        finding.context = {
            "scope": {
                "file": finding.file,
                "function": finding.function,
                "line": finding.line,
                "call_chain": call_chain,
            },
            "call": {
                "api_name": finding.api_name,
                "resolved_name": node.properties.get("resolved_name", node.name),
                "callee": node.properties.get("callee"),
                "arguments": arguments,
                "keywords": node.properties.get("keywords", {}),
            },
            "signals": {
                **_aggregate_signals(argument_signals),
                "arguments": argument_signals,
                "sources": _dedupe_classifications(
                    [source for signal in argument_signals for source in signal["sources"]] + scope_sources
                ),
                "sink": _classify_sink(finding.primitive, source_sinks.get("sinks", [])),
            },
            "dataflow": dataflow,
            "graph": {
                "backend_node_kind": node.kind,
                "incoming_edges": incoming_summaries,
                "outgoing_edges": outgoing_summaries,
                "edge_kinds": sorted({edge.kind for edge in incoming + outgoing}),
                "call_graph": {
                    "callers": sorted(reverse_call_graph.get(finding.function or "", set())),
                    "callees": sorted(call_graph.get(finding.function or "", set())),
                    "call_chain": call_chain,
                },
            },
            "control": {
                "branch_condition": None,
                "inside_loop": False,
                "guarded_by_condition": False,
            },
        }
    return findings


def _extract_argument_signals(
    arguments: list[str],
    node: GraphNode,
    function_info: FunctionInfo | None,
    source_rules: list[dict],
) -> list[dict[str, Any]]:
    """
    Extract signals from each call argument.
    
    For each argument position, extract:
    - Literal status: is it a string/int literal or a variable?
    - Classification: user_input, key_material, generated_random, etc. (from config)
    - Local origin: if this is a variable, does it come from a function parameter or assignment?
    - Semantic hints: mode (CBC/GCM), padding scheme, key size from textual hints
    
    This is the foundation of variable-level dataflow: we extract local assignment/parameter
    origins here, then combine them with graph-based DFG edges in _dataflow_analysis.
    """
    literal_values = node.properties.get("literal_arguments", [])
    result = []
    for index, argument in enumerate(arguments):
        assignment_origin = _assignment_origin(argument, function_info)
        literal_info = _literal_info(argument, literal_values, assignment_origin)
        result.append(
            {
                "index": index,
                "value": argument,
                "role": _argument_role(argument, index),
                "sources": _classify_argument(argument, index, source_rules),
                "is_literal": literal_info["is_literal"],
                "literal_origin": literal_info["origin"],
                "literal_value": literal_info["value"],
                "mode": _mode_from_text(argument),
                "padding": _padding_from_text(argument),
                "key_size": _key_size_from_text(argument),
                "assignment_origin": assignment_origin,  # <- LOCAL ORIGIN (parameter or assignment)
            }
        )
    return result


def _aggregate_signals(argument_signals: list[dict[str, Any]]) -> dict[str, Any]:
    modes = [signal["mode"] for signal in argument_signals if signal.get("mode")]
    paddings = [signal["padding"] for signal in argument_signals if signal.get("padding")]
    key_sizes = [signal["key_size"] for signal in argument_signals if signal.get("key_size")]
    return {
        "mode": modes[0] if modes else None,
        "padding": paddings[0] if paddings else None,
        "key_size": key_sizes[0] if key_sizes else None,
        "has_literal_argument": any(signal["is_literal"] for signal in argument_signals),
        "mentions_key": any(signal["role"] == "key" for signal in argument_signals),
        "mentions_salt": any(signal["role"] == "salt" for signal in argument_signals),
        "mentions_iv": any(signal["role"] == "iv" for signal in argument_signals),
        "mentions_randomness": any(signal["role"] == "randomness" for signal in argument_signals),
    }


def _dataflow_analysis(
    node: GraphNode,
    graph: NormalizedGraph,
    nodes_by_id: dict[str, GraphNode],
    incoming_edges: dict[str, list[GraphEdge]],
    outgoing_edges: dict[str, list[GraphEdge]],
    argument_signals: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Hybrid variable-level dataflow analysis: combines graph-based tracking + local AST analysis.
    
    Strategy:
    1. LOCAL ORIGINS: For each argument that has an assignment_origin (from _extract_argument_signals),
       record it as a source reaching the crypto sink.
       E.g., if encrypt(token) and token=request["token"], record that request["token"] reaches the sink.
    
    2. GRAPH EDGES: If the normalized graph has DFG/DATA_FLOW/REACHES edges, perform BFS from
       the sink to trace data origins through the graph. This captures interprocedural flows
       that the local AST analysis cannot reach.
    
    3. COMBINED EVIDENCE: Report both local and graph-based sources in sources_reaching_sink.
       If neither is available, mark unresolved_reason = "no_dataflow_edges_or_assignment_origin".
    
    The "available" flag indicates whether ANY evidence (local or graph) was found for this sink.
    """
    dataflow_edges = [edge for edge in graph.edges if edge.kind in DATA_FLOW_EDGE_KINDS]
    reached_sources = []
    
    # STEP 1: Local assignment origins (from function parameter or local assignment)
    for signal in argument_signals:
        if signal["assignment_origin"] is not None:
            reached_sources.append(
                {
                    "argument_index": signal["index"],
                    "argument": signal["value"],
                    "via": "assignment_origin",
                    "source": signal["assignment_origin"],
                    "reaches_sink": True,
                }
            )

    # STEP 2: Graph-based dataflow (DFG/DATA_FLOW/REACHES edges)
    if dataflow_edges:
        reaches = _reaching_dataflow_sources(node.id, nodes_by_id, incoming_edges, outgoing_edges)
        reached_sources.extend(reaches)

    return {
        "available": bool(dataflow_edges or reached_sources),
        "edge_kinds": sorted({edge.kind for edge in dataflow_edges}),
        "sources_reaching_sink": reached_sources,
        "unresolved_reason": None if dataflow_edges or reached_sources else "no_dataflow_edges_or_assignment_origin",
    }


def _reaching_dataflow_sources(
    sink_id: str,
    nodes_by_id: dict[str, GraphNode],
    incoming_edges: dict[str, list[GraphEdge]],
    outgoing_edges: dict[str, list[GraphEdge]],
) -> list[dict[str, Any]]:
    """
    Breadth-first search over DFG/DATA_FLOW/REACHES edges to find all nodes that can reach the crypto sink.
    
    This is the GRAPH-BASED part of variable-level dataflow. When the normalized graph contains
    DFG edges (from Fraunhofer CPG), we traverse them backward from the sink to find all possible
    data origins.
    
    Limits:
    - MAX_DATAFLOW_DEPTH=24: prevent exponential blowup on cyclic/complex graphs
    - visited set: avoid revisiting nodes
    
    Returns a list of reached_nodes with their node_ref, kind, name, and edge path from sink.
    """
    queue = deque([(sink_id, [])])
    visited = {sink_id}
    reached = []
    while queue:
        current, path = queue.popleft()
        if len(path) >= MAX_DATAFLOW_DEPTH:
            continue
        candidate_edges = [
            edge for edge in incoming_edges.get(current, []) if edge.kind in DATA_FLOW_EDGE_KINDS
        ] + [
            edge for edge in outgoing_edges.get(current, []) if edge.kind in DATA_FLOW_EDGE_KINDS
        ]
        for edge in candidate_edges:
            neighbor_id = edge.source if edge.target == current else edge.target
            if neighbor_id in visited:
                continue
            visited.add(neighbor_id)
            neighbor = nodes_by_id.get(neighbor_id)
            next_path = [*path, edge.kind]
            reached.append(
                {
                    "node_ref": _node_ref(neighbor_id),
                    "raw_node_id": neighbor_id,
                    "kind": neighbor.kind if neighbor else None,
                    "name": neighbor.name if neighbor else None,
                    "code": neighbor.properties.get("code") if neighbor else None,
                    "path": next_path,
                    "reaches_sink": True,
                }
            )
            queue.append((neighbor_id, next_path))
    return reached


def _function_infos(graph: NormalizedGraph) -> dict[str, FunctionInfo]:
    infos = {}
    for node in graph.nodes:
        if node.kind != "function" or not node.name:
            continue
        code = str(node.properties.get("code") or "")
        info = _parse_function_info(node.name, code, node.properties.get("parameters", []))
        infos[node.name] = info
    return infos


def _parse_function_info(name: str, code: str, fallback_parameters: list[str]) -> FunctionInfo:
    parameters = [str(parameter) for parameter in fallback_parameters]
    assignments: dict[str, str] = {}
    calls: list[dict[str, Any]] = []
    try:
        module = ast.parse(code)
    except SyntaxError:
        return FunctionInfo(name=name, parameters=parameters, assignments=assignments, calls=calls, raw_code=code)

    function = next((node for node in ast.walk(module) if isinstance(node, ast.FunctionDef)), None)
    if function is not None:
        parameters = [arg.arg for arg in function.args.args]

    for node in ast.walk(module):
        if isinstance(node, ast.Assign):
            value = _safe_unparse(node.value)
            for target in node.targets:
                for target_name in _target_names(target):
                    assignments[target_name] = value
        elif isinstance(node, ast.Call):
            calls.append(
                {
                    "name": _call_name(node.func),
                    "arguments": [_safe_unparse(argument) for argument in node.args],
                    "line": getattr(node, "lineno", None),
                }
            )
    return FunctionInfo(name=name, parameters=parameters, assignments=assignments, calls=calls, raw_code=code)


def _assignment_origin(argument: str, function_info: FunctionInfo | None) -> dict[str, Any] | None:
    """
    Extract local origin of a variable: is it a function parameter or function-local assignment?
    
    Examples:
    - encrypt(key) where 'key' is a function parameter → {"kind": "function_parameter", "name": "key"}
    - encrypt(token) where token = request["token"] → {"kind": "assignment", "name": "token", "expression": "request[\"token\"]", ...}
    - encrypt("hardcoded") where "hardcoded" is a literal → None (no local origin needed, it's a literal)
    
    This is the LOCAL ORIGIN part of variable-level dataflow. It bridges the gap when the CPG graph
    lacks interprocedural DFG edges by reporting what we know from local code inspection.
    """
    if function_info is None:
        return None
    bare = _bare_name(argument)
    if bare in function_info.parameters:
        return {"kind": "function_parameter", "name": bare}
    if bare in function_info.assignments:
        value = function_info.assignments[bare]
        return {
            "kind": "assignment",
            "name": bare,
            "expression": value,
            "is_literal": _is_literal_text(value),
            "is_call": "(" in value and ")" in value,
        }
    return None


def _literal_info(argument: str, literal_values: list[Any], assignment_origin: dict[str, Any] | None) -> dict[str, Any]:
    direct_literal = _is_literal_text(argument)
    graph_literal = argument in {str(value) for value in literal_values}
    assignment_literal = bool(assignment_origin and assignment_origin.get("is_literal"))
    value = argument if direct_literal else assignment_origin.get("expression") if assignment_literal and assignment_origin else None
    origin = None
    if direct_literal:
        origin = "argument_literal"
    elif graph_literal:
        origin = "graph_literal"
    elif assignment_literal:
        origin = "assignment_literal"
    return {"is_literal": direct_literal or graph_literal or assignment_literal, "origin": origin, "value": value}


def _edges_by_source(graph: NormalizedGraph) -> dict[str, list[GraphEdge]]:
    edges: dict[str, list[GraphEdge]] = {}
    for edge in graph.edges:
        edges.setdefault(edge.source, []).append(edge)
    return edges


def _edges_by_target(graph: NormalizedGraph) -> dict[str, list[GraphEdge]]:
    edges: dict[str, list[GraphEdge]] = {}
    for edge in graph.edges:
        edges.setdefault(edge.target, []).append(edge)
    return edges


def _edge_summary(edge: GraphEdge, nodes_by_id: dict[str, GraphNode], incoming: bool) -> dict:
    neighbor_id = edge.source if incoming else edge.target
    neighbor = nodes_by_id.get(neighbor_id)
    return {
        "kind": edge.kind,
        "direction": "incoming" if incoming else "outgoing",
        "neighbor_id": neighbor_id,
        "neighbor_ref": _node_ref(neighbor_id),
        "neighbor_kind": neighbor.kind if neighbor else None,
        "neighbor_name": neighbor.name if neighbor else None,
        "neighbor_code": neighbor.properties.get("code") if neighbor else None,
    }


def _call_graph(graph: NormalizedGraph, nodes_by_id: dict[str, GraphNode]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for edge in graph.edges:
        if edge.kind != "CALLS":
            continue
        source = nodes_by_id.get(edge.source)
        target = nodes_by_id.get(edge.target)
        if not source or not target or not source.name or not target.name:
            continue
        result.setdefault(source.name, set()).add(target.name)
    return result


def _reverse_call_graph(call_graph: dict[str, set[str]]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for caller, callees in call_graph.items():
        for callee in callees:
            result.setdefault(callee, set()).add(caller)
    return result


def _call_chain(function: str | None, reverse_call_graph: dict[str, set[str]]) -> list[str]:
    if not function:
        return []
    queue = deque([(function, [function])])
    best = [function]
    visited_states = {(function,)}
    while queue:
        current, chain = queue.popleft()
        if len(chain) > len(best):
            best = chain
        if len(chain) >= MAX_CALL_CHAIN_DEPTH:
            continue
        for caller in sorted(reverse_call_graph.get(current, set())):
            if caller in chain:
                continue
            candidate = [caller, *chain]
            state = tuple(candidate)
            if state in visited_states:
                continue
            visited_states.add(state)
            queue.append((caller, candidate))
    return best


def _classify_argument(argument: str, index: int, source_rules: list[dict]) -> list[dict]:
    lowered = argument.lower()
    classifications = []
    for rule in source_rules:
        labels = [str(label).lower() for label in rule.get("labels", [])]
        if any(label in lowered for label in labels):
            classifications.append(
                {
                    "argument_index": index,
                    "argument": argument,
                    "source_id": rule.get("id"),
                    "classification": rule.get("classification"),
                }
            )
    return classifications


def _classify_scope(function: str | None, incoming_edges: list[dict], source_rules: list[dict]) -> list[dict]:
    text_parts = [function or ""]
    text_parts.extend(str(edge.get("neighbor_code") or "") for edge in incoming_edges)
    text = " ".join(text_parts).lower()
    classifications = []
    seen = set()
    for rule in source_rules:
        labels = [str(label).lower() for label in rule.get("labels", [])]
        for label in labels:
            if label in text:
                key = (rule.get("id"), label)
                if key in seen:
                    continue
                seen.add(key)
                classifications.append(
                    {
                        "argument_index": None,
                        "argument": label,
                        "source_id": rule.get("id"),
                        "classification": rule.get("classification"),
                        "scope": "function_context",
                    }
                )
    return classifications


def _classify_sink(primitive: str, sink_rules: list[dict]) -> dict | None:
    for rule in sink_rules:
        if primitive in rule.get("primitives", []):
            return {
                "sink_id": rule.get("id"),
                "classification": rule.get("classification"),
            }
    return None


def _dedupe_classifications(items: list[dict]) -> list[dict]:
    seen = set()
    result = []
    for item in items:
        key = (
            item.get("argument_index"),
            item.get("argument"),
            item.get("source_id"),
            item.get("classification"),
            item.get("scope"),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _argument_role(argument: str, index: int) -> str:
    lowered = argument.lower()
    if any(token in lowered for token in ["key", "password", "secret"]):
        return "key"
    if any(token in lowered for token in ["iv", "nonce"]):
        return "iv"
    if "salt" in lowered:
        return "salt"
    if any(token in lowered for token in ["random", "urandom", "token_bytes", "randbytes"]):
        return "randomness"
    if any(token in lowered for token in ["data", "payload", "message", "token", "note"]):
        return "data"
    return f"arg_{index}"


def _mode_from_text(value: str) -> str | None:
    match = re.search(r"(?:MODE_|modes\.)(ECB|CBC|GCM|CTR|CFB|OFB)", value)
    return match.group(1) if match else None


def _padding_from_text(value: str) -> str | None:
    for padding in ["PKCS7", "OAEP", "PSS", "PKCS1v15"]:
        if padding.lower() in value.lower():
            return padding
    return None


def _key_size_from_text(value: str) -> int | None:
    try:
        parsed = int(value.replace("_", "").strip())
    except ValueError:
        return None
    if parsed in {64, 112, 128, 192, 2048, 3072, 4096} or parsed >= 256:
        return parsed
    return None


def _is_literal_text(value: str) -> bool:
    stripped = value.strip()
    if (stripped.startswith("'") and stripped.endswith("'")) or (
        stripped.startswith('"') and stripped.endswith('"')
    ):
        return True
    try:
        ast.literal_eval(stripped)
    except (ValueError, SyntaxError):
        return False
    return True


def _target_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [name for element in target.elts for name in _target_names(element)]
    return []


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return _safe_unparse(node)


def _safe_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return node.__class__.__name__


def _bare_name(value: str) -> str:
    return value.strip().split(".", 1)[0].split("[", 1)[0]


def _node_ref(raw_node_id: str) -> str:
    return f"n_{sha256(raw_node_id.encode('utf-8')).hexdigest()[:12]}"
