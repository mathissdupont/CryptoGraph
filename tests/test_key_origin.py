"""Behavioral checks for the bounded origin contract, not a research test set."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

import pytest
from pydantic import ValidationError

from cryptograph.cpg_loader import load_graph
from cryptograph.key_origin import EvidenceStep, KeyOriginClaim, Span, analyze_key_origins, audit_claim_structure
from cryptograph.models import GraphEdge


PREFIX = "import os\nfrom Crypto.Cipher import AES\n\n"


def inspect(tmp_path: Path, body: str, *, graph=True):
    source = tmp_path / "example.py"
    source.write_text(PREFIX + body, encoding="utf-8")
    context = load_graph(source, "ast-lite") if graph else None
    claims = analyze_key_origins(source, context)
    assert all(not audit_claim_structure(claim, source, context) for claim in claims)
    return source, claims


@pytest.mark.parametrize("body,origins,status,modality", [
    ('def f():\n    key = b"fixed"\n    return AES.new(key, AES.MODE_ECB)\n', ["literal"], "resolved", "must"),
    ('def f():\n    return AES.new(os.urandom(16), AES.MODE_ECB)\n', ["csprng_api"], "resolved", "must"),
    ('def f():\n    rng = os.urandom\n    return AES.new(rng(16), AES.MODE_ECB)\n', ["csprng_api"], "resolved", "must"),
    ('def f():\n    key = b"fixed"\n    cipher = AES.new(key, AES.MODE_ECB)\n    key = os.urandom(16)\n    return cipher\n', ["literal"], "resolved", "must"),
    ('def f():\n    key = os.urandom(16)\n    key = b"fixed"\n    return AES.new(key, AES.MODE_ECB)\n', ["literal"], "resolved", "must"),
    ('def f(flag):\n    if flag:\n        key = b"fixed"\n    else:\n        key = os.urandom(16)\n    return AES.new(key, AES.MODE_ECB)\n', ["csprng_api", "literal"], "resolved", "may"),
    ('def f(flag, supplied):\n    key = os.urandom(16) if flag else supplied\n    return AES.new(key, AES.MODE_ECB)\n', ["csprng_api"], "partial", "may"),
    ('def f(key):\n    return AES.new(key, AES.MODE_ECB)\n', [], "abstained", "unknown"),
    ('def f():\n    if False:\n        key = b"fixed"\n    else:\n        key = os.urandom(16)\n    return AES.new(key, AES.MODE_ECB)\n', ["csprng_api"], "resolved", "must"),
    ('def f():\n    key = b"fixed" if True else os.urandom(16)\n    return AES.new(key, AES.MODE_ECB)\n', ["literal"], "resolved", "must"),
    ('def f():\n    key = os.environ["KEY"].encode()\n    return AES.new(key, AES.MODE_ECB)\n', ["external_configuration"], "resolved", "must"),
    ('def f():\n    key = os.getenv("KEY", "fixed").encode()\n    return AES.new(key, AES.MODE_ECB)\n', ["external_configuration", "literal"], "resolved", "may"),
    ('def f(os):\n    key = os.urandom(16)\n    return AES.new(key, AES.MODE_ECB)\n', [], "abstained", "unknown"),
    ('def f():\n    key = os.urandom(16)\n    import os\n    return AES.new(key, AES.MODE_ECB)\n', [], "abstained", "unknown"),
    ('def f():\n    unknown_mutator()\n    key = os.urandom(16)\n    return AES.new(key, AES.MODE_ECB)\n', [], "abstained", "unknown"),
    ('def f():\n    key = b"fixed"\n    while flag:\n        key = os.urandom(16)\n    return AES.new(key, AES.MODE_ECB)\n', [], "abstained", "unknown"),
    ('def f(key):\n    (key := os.urandom(16))\n    return AES.new(key, AES.MODE_ECB)\n', [], "abstained", "unknown"),
    ('def f():\n    key = b"fixed"\n    return AES.new(key, key=os.urandom(16), mode=AES.MODE_ECB)\n', [], "abstained", "unknown"),
    ('key = b"fixed"\ncipher = AES.new(key, AES.MODE_ECB)\n', ["literal"], "resolved", "must"),
])
def test_source_order_bindings_and_alternatives(tmp_path, body, origins, status, modality):
    _, claims = inspect(tmp_path, body)
    assert len(claims) == 1
    assert (claims[0].origins, claims[0].status, claims[0].modality) == (origins, status, modality)


def test_unsupported_loop_keeps_assignment_boundary_without_resolving_origin(tmp_path):
    _, claims = inspect(tmp_path, 'def f(flag):\n    key = b"fixed"\n    while flag:\n        key = os.urandom(16)\n    return AES.new(key, AES.MODE_ECB)\n')
    assert claims[0].immediate_boundary == "local_assignment"
    assert claims[0].status == "abstained" and claims[0].origins == []
    assert "unsupported_write" in claims[0].unresolved_reasons


def test_import_alias_preserves_api_identity(tmp_path):
    _, claims = inspect(tmp_path, 'from os import urandom as rng\ndef f():\n    return AES.new(rng(16), AES.MODE_ECB)\n')
    assert claims[0].origins == ["csprng_api"]


@pytest.mark.parametrize("graph", [True, False])
def test_wrapper_needs_source_binding_and_graph_witness(tmp_path, graph):
    _, claims = inspect(tmp_path,
        'def fake_urandom(n):\n    return b"0" * n\n\ndef f():\n    return AES.new(fake_urandom(16), AES.MODE_ECB)\n', graph=graph)
    assert claims[0].origins == (["literal"] if graph else [])
    assert claims[0].status == ("resolved" if graph else "abstained")


def test_actual_formal_binding_is_recorded(tmp_path):
    _, claims = inspect(tmp_path,
        'def helper(value):\n    return value\n\ndef f():\n    return AES.new(helper(os.urandom(16)), AES.MODE_ECB)\n')
    assert claims[0].origins == ["csprng_api"]
    assert any(step.kind == "actual_formal_binding" for step in claims[0].evidence)


def test_reversed_or_cross_file_edges_do_not_authorize_wrapper(tmp_path):
    path, _ = inspect(tmp_path, 'def helper():\n    return os.urandom(16)\n\ndef f():\n    return AES.new(helper(), AES.MODE_ECB)\n')
    graph = load_graph(path, "ast-lite")
    graph.edges = [GraphEdge(source=edge.target, target=edge.source, kind=edge.kind) if edge.kind == "CALLS" else edge for edge in graph.edges]
    assert analyze_key_origins(path, graph)[0].status == "abstained"
    graph = load_graph(path, "ast-lite")
    for node in graph.nodes:
        node.file = "unrelated.py"
    assert analyze_key_origins(path, graph)[0].status == "abstained"


def test_unknown_side_effect_in_helper_does_not_escape(tmp_path):
    _, claims = inspect(tmp_path,
        'def helper():\n    unknown_mutator()\n    return os.urandom(16)\n\ndef f():\n    helper()\n    return AES.new(os.urandom(16), AES.MODE_ECB)\n')
    assert claims[0].status == "abstained"


def test_shadowed_crypto_class_is_not_a_verified_target(tmp_path):
    _, claims = inspect(tmp_path, 'def f(AES):\n    return AES.new(b"fixed", 1)\n')
    assert claims == []


def test_explicit_api_mutation_forces_abstention(tmp_path):
    _, claims = inspect(tmp_path, 'os.urandom = lambda n: b"0" * n\ndef f():\n    return AES.new(os.urandom(16), AES.MODE_ECB)\n')
    assert claims[0].status == "abstained"


def test_unsupported_control_preserves_visible_target_as_abstention(tmp_path):
    _, claims = inspect(tmp_path, 'def f(key):\n    while flag:\n        cipher = AES.new(key, AES.MODE_ECB)\n')
    assert len(claims) == 1 and claims[0].status == "abstained"


def test_pyca_constructor_and_two_calls_on_one_line(tmp_path):
    _, claims = inspect(tmp_path,
        'from cryptography.hazmat.primitives.ciphers import algorithms\ndef f():\n    a = algorithms.AES(b"first"); b = algorithms.AES(os.urandom(16))\n')
    assert [claim.origins for claim in claims] == [["literal"], ["csprng_api"]]
    assert len({claim.operation_id for claim in claims}) == 2


def test_analysis_does_not_execute_target_source(tmp_path):
    sentinel = tmp_path / "executed.txt"
    _, claims = inspect(tmp_path,
        f'open({str(sentinel)!r}, "w").write("executed")\ndef f():\n    return AES.new(b"fixed", AES.MODE_ECB)\n')
    assert not sentinel.exists()
    assert claims[0].status == "abstained"


def test_audit_rejects_source_change_and_invalid_span(tmp_path):
    source, claims = inspect(tmp_path, 'def f():\n    return AES.new(b"fixed", AES.MODE_ECB)\n')
    original = claims[0]
    source.write_text(source.read_text(encoding="utf-8") + "# changed\n", encoding="utf-8")
    assert "source_hash_mismatch" in audit_claim_structure(original, source)
    forged = original.model_copy(update={"target": original.target.model_copy(update={"line": 999})})
    assert "target_is_not_source_call" in audit_claim_structure(forged, source)


def test_audit_rejects_cyclic_evidence(tmp_path):
    source, claims = inspect(tmp_path, 'def f():\n    return AES.new(b"fixed", AES.MODE_ECB)\n')
    claim = claims[0]
    step = claim.evidence[0].model_copy(update={"parents": [claim.evidence[0].id]})
    forged = claim.model_copy(update={"evidence": [step, *claim.evidence[1:]]})
    assert "cyclic_evidence" in audit_claim_structure(forged, source)


def test_contract_rejects_inconsistent_modality(tmp_path):
    _, claims = inspect(tmp_path, 'def f(key):\n    return AES.new(key, AES.MODE_ECB)\n')
    payload = claims[0].model_dump()
    payload["modality"] = "must"
    with pytest.raises(ValidationError):
        KeyOriginClaim.model_validate(payload)


def test_hash_covers_raw_crlf_bytes(tmp_path):
    source = tmp_path / "example.py"
    raw = (PREFIX + 'key = b"fixed"\ncipher = AES.new(key, AES.MODE_ECB)\n').replace("\n", "\r\n").encode()
    source.write_bytes(raw)
    claim = analyze_key_origins(source)[0]
    assert claim.source_sha256 == hashlib.sha256(raw).hexdigest()
    assert not audit_claim_structure(claim, source)


@pytest.mark.parametrize("body", [
    'def f(flag):\n    unused = mutate() if flag else None\n    return AES.new(os.urandom(16), AES.MODE_ECB)\n',
    'def g(value=mutate()):\n    pass\ndef f():\n    return AES.new(os.urandom(16), AES.MODE_ECB)\n',
    'def f(supplied):\n    unused = supplied.attribute\n    return AES.new(os.urandom(16), AES.MODE_ECB)\n',
    'def f(supplied):\n    unused = supplied[0]\n    return AES.new(os.urandom(16), AES.MODE_ECB)\n',
])
def test_unmodeled_effects_do_not_get_lost(tmp_path, body):
    _, claims = inspect(tmp_path, body)
    assert claims[0].status == "abstained"


def test_graph_witness_is_checked_against_retained_graph(tmp_path):
    source, _ = inspect(tmp_path, 'def helper():\n    return os.urandom(16)\n\ndef f():\n    return AES.new(helper(), AES.MODE_ECB)\n')
    graph = load_graph(source, "ast-lite")
    claim = analyze_key_origins(source, graph)[0]
    assert claim.graph_features_used == ["CALLS"]
    assert "graph_witness_unchecked" in audit_claim_structure(claim, source)
    graph.edges = []
    assert "invalid_graph_witness" in audit_claim_structure(claim, source, graph)


def test_audit_flags_a_forged_post_target_assignment(tmp_path):
    source, claims = inspect(tmp_path,
        'def f():\n    key = b"fixed"\n    cipher = AES.new(key, AES.MODE_ECB)\n    key = os.urandom(16)\n    return cipher\n')
    node = [node for node in ast.walk(ast.parse(source.read_text())) if isinstance(node, ast.Assign)][-1]
    step = EvidenceStep(id="forged", kind="assignment", detail="key", parents=[],
        span=Span(file=source.name, line=node.lineno, column=node.col_offset, end_line=node.end_lineno, end_column=node.end_col_offset))
    forged = claims[0].model_copy(update={"evidence": [*claims[0].evidence, step]})
    assert "local_assignment_after_target" in audit_claim_structure(forged, source)
