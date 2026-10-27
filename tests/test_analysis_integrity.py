"""Regression tests for integrity of reported cryptographic analysis.

These tests deliberately use tiny synthetic graphs to assert what can and cannot
be inferred, independent of optional JVM/Fraunhofer setup.
"""
from __future__ import annotations

from cryptograph.context_extractor import _dataflow_analysis, _reaching_dataflow_sources
from cryptograph.models import GraphEdge, GraphNode, NormalizedGraph
from cryptograph.risk_engine import RiskEngine


def _node(identifier: str) -> GraphNode:
    return GraphNode(id=identifier, kind="variable", name=identifier, file="sample.py")


def test_dataflow_only_traverses_upstream_origins():
    nodes = {name: _node(name) for name in ("source", "sink", "downstream")}
    edges = [
        GraphEdge(source="source", target="sink", kind="DFG"),
        GraphEdge(source="sink", target="downstream", kind="DFG"),
    ]
    incoming = {
        "sink": [edges[0]],
        "downstream": [edges[1]],
    }
    outgoing = {
        "source": [edges[0]],
        "sink": [edges[1]],
    }
    sources = _reaching_dataflow_sources("sink", nodes, incoming, outgoing)
    assert {row["name"] for row in sources} == {"source"}
    assert all(row["reaches_sink"] for row in sources)


def test_unrelated_graph_dataflow_does_not_claim_sink_is_traced():
    graph = NormalizedGraph(
        backend="test", root="sample.py",
        nodes=[_node("sink"), _node("other1"), _node("other2")],
        edges=[GraphEdge(source="other1", target="other2", kind="DFG")],
    )
    nodes = {node.id: node for node in graph.nodes}
    incoming = {"other2": [graph.edges[0]]}
    outgoing = {"other1": [graph.edges[0]]}
    finding_flow = _dataflow_analysis(
        nodes["sink"], graph, nodes, incoming, outgoing, [],
    )
    assert finding_flow["available"] is False
    assert finding_flow["sources_reaching_sink"] == []
    assert finding_flow["unresolved_reason"] == "no_dataflow_edges_or_assignment_origin"


def test_unknown_algorithm_is_not_assumed_low_risk():
    score = RiskEngine().score(
        algorithm="Unrecognized-Cipher", primitive="symmetric_encryption",
        provider=None, arguments=[], api_name="mystery.encrypt", context={},
    )
    assert score.level == "medium"
    assert "algorithm_needs_review" in score.tags
    assert score.derivation["algorithm_unclassified"] is True
