from __future__ import annotations

import json
from uuid import uuid4
from pathlib import Path

from cryptograph.cbom_builder import build_cbom
from cryptograph.context_extractor import enrich_context
from cryptograph.cpg_loader import load_graph
from cryptograph.cpg_visualizer import write_dot, write_graph_json, write_html
from cryptograph.crypto_matcher import find_crypto_calls
from cryptograph.models import GraphNode, NormalizedGraph
from cryptograph.orchestrator import _config_language_for, export_cbom_to_jsonl
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


def test_ruby_lite_detects_crypto_calls(tmp_path) -> None:
    ruby_source = tmp_path / "sample.rb"
    ruby_source.write_text(
        """
require 'openssl'
require 'securerandom'

def encrypt(password)
  Digest::MD5.hexdigest(password)
  OpenSSL::Cipher.new('AES-128-ECB')
  SecureRandom.bytes(32)
end
""".strip()
        + "\n",
        encoding="utf-8",
    )

    graph = load_graph(ruby_source, backend="ast-lite")
    findings = find_crypto_calls(
        graph,
        project_path("config", "api_mappings.ruby.json"),
        project_path("config", "rules_v2.ruby.json"),
    )

    api_names = {finding.api_name for finding in findings}

    assert graph.backend == "ruby-lite"
    assert "Digest::MD5.hexdigest" in api_names
    assert "OpenSSL::Cipher.new" in api_names
    assert "SecureRandom.bytes" in api_names


def test_c_cpp_lite_detects_openssl_tls_calls(tmp_path) -> None:
    source = tmp_path / "tls.cpp"
    source.write_text(
        """
#include <openssl/ssl.h>

SSL_CTX* make_context() {
  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL");
  SSL_CTX_load_verify_locations(ctx, "ca.pem", nullptr);
  return ctx;
}

void send_record(SSL *ssl, const char *message) {
  SSL_connect(ssl);
  SSL_write(ssl, message, 42);
}
""".strip()
        + "\n",
        encoding="utf-8",
    )

    graph = load_graph(source, backend="ast-lite")
    findings = find_crypto_calls(
        graph,
        project_path("config", "api_mappings.c_cpp.json"),
        project_path("config", "rules_v2.c_cpp.json"),
    )

    api_names = {finding.api_name for finding in findings}

    assert graph.backend == "c-cpp-lite"
    assert {"SSL_CTX_new", "TLS_client_method", "SSL_CTX_set_cipher_list", "SSL_connect", "SSL_write"} <= api_names


def test_language_specific_mapping_schema_is_supported() -> None:
    from cryptograph.crypto_matcher_v2 import find_crypto_calls as find_crypto_calls_v2

    graph = NormalizedGraph(
        backend="test",
        root=".",
        nodes=[
            GraphNode(
                id="n1",
                kind="call",
                name="hashlib.md5",
                file="sample.py",
                line=1,
                properties={"arguments": ["'abc'"], "resolved_name": "hashlib.md5", "callee": "hashlib.md5"},
            )
        ],
        edges=[],
    )

    findings = find_crypto_calls_v2(
        graph,
        project_path("config", "api_mappings.python.json"),
        project_path("config", "rules_v2.python.json"),
    )

    assert findings
    assert findings[0].api_name == "hashlib.md5"


def test_config_language_aliases() -> None:
    assert _config_language_for("kotlin") == "java"
    assert _config_language_for("typescript") == "javascript"
    assert _config_language_for("c") == "c_cpp"
    assert _config_language_for("cpp") == "c_cpp"
    assert _config_language_for("java") == "java"


def test_rules_mode_in_and_key_size_less_than_are_evaluated() -> None:
    from cryptograph.crypto_matcher_v2 import find_crypto_calls as find_crypto_calls_v2

    graph = NormalizedGraph(
        backend="test",
        root=".",
        nodes=[
            GraphNode(
                id="n-ts-1",
                kind="call",
                name="createCipher",
                file="sample.ts",
                line=10,
                properties={
                    "arguments": ["'AES-128-ECB'"],
                    "resolved_name": "createCipher",
                    "callee": "createCipher",
                    "literal_arguments": ["AES-128-ECB"],
                },
            ),
            GraphNode(
                id="n-cs-1",
                kind="call",
                name="RSA.Create",
                file="sample.cs",
                line=20,
                properties={
                    "arguments": ["1024"],
                    "resolved_name": "RSA.Create",
                    "callee": "RSA.Create",
                    "literal_arguments": [],
                },
            ),
        ],
        edges=[],
    )

    ts_findings = find_crypto_calls_v2(
        NormalizedGraph(backend=graph.backend, root=graph.root, nodes=[graph.nodes[0]], edges=[]),
        project_path("config", "api_mappings.typescript.json"),
        project_path("config", "rules_v2.typescript.json"),
    )
    assert ts_findings
    assert "TS_AES_ECB" in ts_findings[0].rule_ids

    cs_findings = find_crypto_calls_v2(
        NormalizedGraph(backend=graph.backend, root=graph.root, nodes=[graph.nodes[1]], edges=[]),
        project_path("config", "api_mappings.csharp.json"),
        project_path("config", "rules_v2.csharp.json"),
    )
    assert cs_findings
    assert "CSHARP_RSA_SMALL_KEY" in cs_findings[0].rule_ids


def test_export_cbom_to_jsonl_includes_metadata(tmp_path: Path) -> None:
    merged = {
        "cboms": [
            {
                "metadata": {
                    "detected_language": "javascript",
                    "backend": "fraunhofer-cpg",
                    "source": "repo/src",
                    "run_id": "run-123",
                },
                "cryptographic_assets": [
                    {
                        "asset_id": "asset-1",
                        "crypto_metadata": {"algorithm": "AES", "primitive": "symmetric_encryption"},
                        "usage": {"operation": "encryption"},
                        "context": {"file": "index.js", "function": "encrypt", "call_chain": ["encrypt"]},
                        "flow": {},
                        "control": {},
                        "graph_context": {},
                        "rules": [],
                        "evidence": {"summary": {"api_call": "createCipher"}},
                    }
                ],
            }
        ]
    }
    out = tmp_path / "dataset.jsonl"
    count = export_cbom_to_jsonl(merged, out)
    assert count == 1

    row = json.loads(out.read_text(encoding="utf-8").splitlines()[0])
    assert row["input"]["metadata"]["detected_language"] == "javascript"
    assert row["input"]["metadata"]["backend"] == "fraunhofer-cpg"
    assert row["input"]["metadata"]["source"] == "repo/src"
    assert row["input"]["metadata"]["run_id"] == "run-123"
