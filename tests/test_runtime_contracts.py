"""Regressions for output paths, installed defaults and backend provenance."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from cryptograph.cpg_loader import CpgLoadError, load_graph
from cryptograph.main import main
from cryptograph.models import NormalizedGraph
from cryptograph.models import CryptoFinding
from cryptograph.algorithm_normalizer import normalize_finding
from cryptograph.utils import new_run_dir


@pytest.mark.parametrize("argument,mode", [
    ('"AES/ECB/PKCS5Padding"', "ECB"),
    ('"AES/GCM/NoPadding"', "GCM"),
    ("configured_transformation", "unknown"),
])
def test_java_transformation_mode_requires_literal(argument: str, mode: str) -> None:
    finding = CryptoFinding(
        api_name="Cipher.getInstance", node_id="call", file="Example.java",
        line=1, function="example", algorithm="AES", primitive="symmetric_encryption",
        arguments=[argument],
    )
    assert normalize_finding(finding).mode == mode


def test_absolute_scan_output_honors_report(tmp_path: Path) -> None:
    source = tmp_path / "example.py"
    source.write_text("import hashlib\nhashlib.md5(b'example')\n", encoding="utf-8")
    report = tmp_path / "report.html"
    assert main([
        "scan", "--input", str(source), "--backend", "ast-lite",
        "--output", str(tmp_path / "cbom.json"), "--report", str(report),
    ]) == 0
    assert "hashlib.md5" in report.read_text(encoding="utf-8")


def test_default_run_directory_is_in_working_directory(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert new_run_dir().parent == tmp_path / "output"


def test_strict_ruby_requires_exporter(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "example.rb"
    source.write_text("require 'openssl'\nOpenSSL::Cipher.new('AES-128-ECB')\n", encoding="utf-8")
    monkeypatch.delenv("CRYPTOGRAPH_FRAUNHOFER_EXPORTER", raising=False)
    with pytest.raises(CpgLoadError, match="artifact not found"):
        load_graph(source, "fraunhofer-strict")
    assert load_graph(source, "ast-lite").backend == "ruby-lite"


def test_strict_mode_rejects_legacy_exporter_boundary_fallback(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "example.py"
    source.write_text("import hashlib\nhashlib.md5(b'example')\n", encoding="utf-8")
    exporter = tmp_path / "exporter.jar"
    exporter.touch()
    monkeypatch.setenv("CRYPTOGRAPH_FRAUNHOFER_EXPORTER", str(exporter))

    def export(command, **kwargs):
        destination = Path(command[command.index("--output") + 1])
        graph = NormalizedGraph(backend="fraunhofer-cpg-boundary", root=str(source))
        destination.write_text(json.dumps(graph.model_dump()), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr("cryptograph.cpg_loader.subprocess.run", export)
    with pytest.raises(CpgLoadError, match="boundary fallback"):
        load_graph(source, "fraunhofer-strict")


@pytest.mark.parametrize("backend", ["fraunhofer", "fraunhofer-strict"])
def test_empty_cpp_export_respects_fallback_policy(tmp_path: Path, monkeypatch, backend: str) -> None:
    source = tmp_path / "example.cpp"
    source.write_text("void f() { SSL_connect(ssl); }\n", encoding="utf-8")
    exporter = tmp_path / "exporter.jar"
    exporter.touch()
    monkeypatch.setenv("CRYPTOGRAPH_FRAUNHOFER_EXPORTER", str(exporter))

    def export(command, **kwargs):
        destination = Path(command[command.index("--output") + 1])
        graph = NormalizedGraph(backend="fraunhofer", root=str(source))
        destination.write_text(json.dumps(graph.model_dump()), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr("cryptograph.cpg_loader.subprocess.run", export)
    if backend == "fraunhofer-strict":
        with pytest.raises(CpgLoadError, match=r"no usable C/C\+\+ calls"):
            load_graph(source, backend)
    else:
        assert load_graph(source, backend).backend == "c-cpp-lite"
