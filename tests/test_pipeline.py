from __future__ import annotations

import json
from uuid import uuid4

from cryptograph.cbom_builder import build_cbom
from cryptograph.context_extractor import enrich_context
from cryptograph.cpg_loader import load_graph
from cryptograph.cpg_visualizer import write_dot, write_graph_json, write_html
from cryptograph.crypto_matcher import find_crypto_calls
from cryptograph.report_builder import build_html_report
from cryptograph.utils import project_path


def test_ast_lite_detects_expected_sample_crypto() -> None:
    graph = load_graph(project_path("samples"), backend="ast-lite")
    findings = find_crypto_calls(
        graph,
        project_path("config", "api_mappings.json"),
        project_path("config", "rules.json"),
    )
    api_names = {finding.api_name for finding in findings}

    assert "AES.new" in api_names
    assert "hashlib.pbkdf2_hmac" in api_names
    assert "RSA.generate" in api_names
    assert "CALLS" in {edge.kind for edge in graph.edges}


def test_adversarial_crypto_patterns_detect_aliases_wrappers_and_flow() -> None:
    graph = load_graph(project_path("samples", "adversarial_crypto_patterns.py"), backend="ast-lite")
    findings = find_crypto_calls(
        graph,
        project_path("config", "api_mappings.json"),
        project_path("config", "rules.json"),
    )
    findings = enrich_context(findings, graph)
    api_names = {finding.api_name for finding in findings}
    functions = {finding.function for finding in findings}

    assert "AES.new" in api_names
    assert "hashlib.pbkdf2_hmac" in api_names
    assert "Cipher" in api_names
    assert "algorithms.AES" in api_names
    assert "modes.CBC" in api_names
    assert "modes.CTR" in api_names
    assert "HMAC" in api_names
    assert "os.urandom" in api_names
    assert "adversarial_crypto_patterns._pycryptodome_wrapper" in functions
    assert "adversarial_crypto_patterns.nested_hazmat_pipeline" in functions
    assert "adversarial_crypto_patterns._mac" in functions
    assert "CALLS" in {edge.kind for edge in graph.edges}

    cbom = build_cbom(findings, source="samples/adversarial_crypto_patterns.py", backend=graph.backend, graph=graph)
    algorithms = {asset["crypto_metadata"]["algorithm"] for asset in cbom["cryptographic_assets"]}
    assert {"AES", "Cipher", "PBKDF2", "HMAC", "CSPRNG"} <= algorithms


def test_rules_mark_aes_ecb_high_risk() -> None:
    graph = load_graph(project_path("samples", "insecure_aes.py"), backend="ast-lite")
    findings = find_crypto_calls(
        graph,
        project_path("config", "api_mappings.json"),
        project_path("config", "rules.json"),
    )
    aes = next(finding for finding in findings if finding.api_name == "AES.new")

    assert aes.risk == "high"
    assert "AES_ECB_MODE" in aes.rule_ids


def test_cbom_builder_returns_summary() -> None:
    graph = load_graph(project_path("samples"), backend="ast-lite")
    findings = find_crypto_calls(
        graph,
        project_path("config", "api_mappings.json"),
        project_path("config", "rules.json"),
    )
    findings = enrich_context(findings, graph)
    cbom = build_cbom(findings, source="samples", backend=graph.backend)

    assert cbom["cbom_format"] == "cryptograph-custom"
    assert cbom["spec_version"] == "0.2"
    assert cbom["analysis"]["graph"]["available"] is False
    assert cbom["summary"]["total_assets"] >= 5
    assert cbom["summary"]["by_primitive"]["key_derivation"] >= 1
    aes = next(
        asset
        for asset in cbom["cryptographic_assets"]
        if asset["evidence"]["api_call"] == "AES.new" and asset["context"]["file"] == "insecure_aes.py"
    )
    assert aes["asset_id"].startswith("crypto-")
    assert aes["crypto_metadata"]["mode"] == "ECB"
    assert aes["usage"]["operation"] == "encryption"
    assert aes["flow"]["key_source"] in {"function_parameter", "classified_key_material"}
    assert "iv_source" in aes["flow"]
    assert "confidence" in aes["risk"]
    assert isinstance(aes["risk"]["confidence"], float)
    assert "node_ref" in aes["evidence"]
    assert "raw_node_id" in aes["evidence"]
    assert "insecure_mode" in aes["risk"]["tags"]

    cbom_with_graph = build_cbom(findings, source="samples", backend=graph.backend, graph=graph, run_id="test-run")
    assert cbom_with_graph["metadata"]["run_id"] == "test-run"
    assert cbom_with_graph["analysis"]["graph"]["available"] is True

    auth_aes = next(
        asset
        for asset in cbom_with_graph["cryptographic_assets"]
        if asset["evidence"]["api_call"] == "AES.new" and asset["context"]["file"] == "auth_flow.py"
    )
    assert auth_aes["context"]["call_chain"] == [
        "auth_flow.login",
        "auth_flow.encrypt_auth_token",
    ]
    assert auth_aes["flow"]["source_to_sink"]["inferred"] is True
    assert auth_aes["flow"]["data_source"] == "classified_user_input"


def test_report_builder_writes_html() -> None:
    graph = load_graph(project_path("samples"), backend="ast-lite")
    findings = find_crypto_calls(
        graph,
        project_path("config", "api_mappings.json"),
        project_path("config", "rules.json"),
    )
    findings = enrich_context(findings, graph)
    cbom = build_cbom(findings, source="samples", backend=graph.backend)
    run_id = uuid4().hex
    json_path = project_path("output", f"test-result-{run_id}.json")
    html_path = project_path("output", f"test-report-{run_id}.html")
    json_path.write_text(json.dumps(cbom), encoding="utf-8")

    build_html_report(json_path, html_path)

    html = html_path.read_text(encoding="utf-8")
    assert "CryptoGraph Report" in html
    assert "AES.new" in html
    assert "Risk Summary" in html


def test_graph_visualizer_writes_debug_artifacts() -> None:
    graph = load_graph(project_path("samples"), backend="ast-lite")
    run_id = uuid4().hex
    json_path = project_path("output", f"test-cpg-{run_id}.json")
    dot_path = project_path("output", f"test-cpg-{run_id}.dot")
    html_path = project_path("output", f"test-cpg-{run_id}.html")

    write_graph_json(graph, json_path)
    write_dot(graph, dot_path)
    write_html(graph, html_path)

    graph_json = json.loads(json_path.read_text(encoding="utf-8"))
    dot = dot_path.read_text(encoding="utf-8")
    graph_html = html_path.read_text(encoding="utf-8")

    assert graph_json["backend"] == "ast-lite"
    assert "digraph CryptoGraphCPG" in dot
    assert "CryptoGraph CPG Viewer" in graph_html
    assert "AES.new" in graph_html
