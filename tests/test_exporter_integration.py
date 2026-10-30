"""Opt-in real JVM checks; no exporter is downloaded by the test suite."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from cryptograph.cpg_loader import CpgLoadError, load_graph
from cryptograph.cbom_builder_v2 import build_cbom
from cryptograph.context_extractor import enrich_context
from cryptograph.crypto_matcher_v2 import find_crypto_calls
from cryptograph.utils import project_path


EXPORTER = os.environ.get("CRYPTOGRAPH_TEST_EXPORTER")
pytestmark = pytest.mark.skipif(not EXPORTER, reason="Set CRYPTOGRAPH_TEST_EXPORTER to a built exporter JAR.")


def test_real_java_export_matches_cipher_call(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CRYPTOGRAPH_FRAUNHOFER_EXPORTER", str(EXPORTER))
    source = tmp_path / "CryptoExample.java"
    source.write_text(
        'import javax.crypto.Cipher;\nclass CryptoExample {\n'
        '  static Cipher cipher() throws Exception {\n'
        '    return Cipher.getInstance("AES/ECB/PKCS5Padding");\n  }\n}\n',
        encoding="utf-8",
    )
    graph = load_graph(source, "fraunhofer-strict")
    assert graph.backend == "fraunhofer-cpg"
    findings = find_crypto_calls(
        graph, project_path("config", "api_mappings.java.json"),
        project_path("config", "rules_v2.java.json"),
    )
    assert any("getInstance" in finding.api_name for finding in findings)
    findings = enrich_context(findings, graph)
    cbom = build_cbom(findings, source=str(source), backend=graph.backend, graph=graph)
    aes = next(asset for asset in cbom["cryptographic_assets"] if asset["crypto_metadata"]["algorithm"] == "AES")
    assert aes["crypto_metadata"]["mode"] == "ECB"
    assert aes["risk"]["level"] in {"high", "critical"}


def test_real_exporter_rejects_unsupported_input(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CRYPTOGRAPH_FRAUNHOFER_EXPORTER", str(EXPORTER))
    source = tmp_path / "unsupported.txt"
    source.write_text("not source code\n", encoding="utf-8")
    with pytest.raises(CpgLoadError, match="No supported source files"):
        load_graph(source, "fraunhofer-strict")


def test_opt_in_dfg_export_keeps_assignment_predecessors(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CRYPTOGRAPH_FRAUNHOFER_EXPORTER", str(EXPORTER))
    monkeypatch.setenv("CRYPTOGRAPH_DFG_DEPTH", "8")
    source = tmp_path / 'FlowExample.java'
    source.write_text('class FlowExample {\n static void use(String value) {}\n static void f() {\n String key = "fixed";\n use(key);\n }\n}\n', encoding='utf-8')
    graph = load_graph(source, 'fraunhofer-strict')
    assert graph.export_metadata['dfg_backward_depth'] == 8
    assert any(node.properties.get('code') == '"fixed"' for node in graph.nodes)
    assert any(edge.kind == 'DFG' for edge in graph.edges)
    assert all('source_region' in node.properties for node in graph.nodes)


def test_nested_crypto_constructor_remains_a_detectable_call(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv('CRYPTOGRAPH_FRAUNHOFER_EXPORTER', str(EXPORTER))
    source = tmp_path / 'NestedCipher.java'
    source.write_text('import javax.crypto.Cipher;\nclass NestedCipher {\n static Cipher wrap(Cipher x) {return x;}\n static Cipher f() throws Exception {\n return wrap(Cipher.getInstance("AES/ECB/PKCS5Padding"));\n }\n}\n', encoding='utf-8')
    graph = load_graph(source, 'fraunhofer-strict')
    findings = find_crypto_calls(graph, project_path('config', 'api_mappings.java.json'), project_path('config', 'rules_v2.java.json'))
    assert any('getInstance' in item.api_name for item in findings)
