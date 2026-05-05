"""
CPG Graph Loader and Normalization

This module isolates the CPG backend (Fraunhofer or ast-lite) behind a unified interface.

Normalization:
- Fraunhofer CPG JSON → NormalizedGraph JSON
- AST-lite Python AST → NormalizedGraph JSON

Normalized Graph Structure:
- nodes: function, call, argument, variable, assignment, return, literal nodes with stable IDs
- edges: CALLS, AST, ARGUMENT, RETURN (AST/CFG) + DFG, DATA_FLOW, REACHES (dataflow)
- backend: "fraunhofer", "ast-lite", "fraunhofer-fallback:ast-lite", or "fraunhofer-failed:ast-lite"

Propagation Normalization:
The exporter must normalize assignment/return/call-argument propagation nodes explicitly:
- assignment node: var = expression (tracks variable origin)
- return node: return value (tracks what leaves a function)
- call-argument propagation: actual → formal parameter binding
These nodes and their edges enable variable-level dataflow analysis in context_extractor.py

Backend Isolation:
- JVM (Fraunhofer) runs in a subprocess, not in-process
- Python code never depends on Fraunhofer classes directly
- All communication is via JSON files (cpg_loader ↔ exporter subprocess)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

from cryptograph.ast_lite import build_ast_lite_graph
from cryptograph.cbom import extract_cbom
from cryptograph.c_cpp_lite import build_c_cpp_lite_graph, looks_like_c_cpp
from cryptograph.models import GraphNode, NormalizedGraph
from cryptograph.ruby_lite import build_ruby_lite_graph


class CpgLoadError(RuntimeError):
    pass


def load_graph(input_path: Path, backend: str = "fraunhofer") -> NormalizedGraph:
    """
    Load and normalize a graph from the specified source using the given backend.
    
    Args:
        input_path: Directory containing Python source files to analyze.
        backend: "fraunhofer" (with fallback), "fraunhofer-strict" (fail if CPG fails),
                 or "ast-lite" (lightweight Python AST, no JVM).
    
    Returns:
        NormalizedGraph with nodes and edges in a uniform schema independent of backend.
    
    Backend-specific behavior:
    - fraunhofer: Attempts JVM exporter; on failure, falls back to ast-lite with warning.
    - fraunhofer-strict: Fails immediately if exporter fails (no fallback).
    - ast-lite: Direct Python AST parsing, no JVM dependency.
    """
    input_path = input_path.resolve()
    if _looks_like_ruby(input_path):
        graph = build_ruby_lite_graph(input_path)
        graph.backend = "ruby-lite"
        return graph
    if backend == "ast-lite" and looks_like_c_cpp(input_path):
        return build_c_cpp_lite_graph(input_path)
    if backend == "ast-lite":
        # detect non-Python files at the top-level and warn the user
        if input_path.is_dir():
            other_exts = {".java": "Java", ".c": "C", ".cpp": "C++", ".h": "C/C++ headers", ".js": "JavaScript", ".ts": "TypeScript", ".go": "Go", ".cs": "C#"}
            detected = set()
            for path in input_path.iterdir():
                if path.is_file():
                    ext = path.suffix.lower()
                    if ext in other_exts:
                        detected.add(other_exts[ext])
            if detected:
                print(
                    f"[cryptograph][warning] Detected non-Python files: {', '.join(sorted(detected))}. "
                    "You requested the 'ast-lite' backend; ast-lite only parses Python. "
                    "For multi-language CPGs use the Fraunhofer exporter (set CRYPTOGRAPH_FRAUNHOFER_EXPORTER) or run inside Docker.",
                    file=sys.stderr,
                )
        return build_ast_lite_graph(input_path)
    if backend == "fraunhofer":
        return _load_with_fraunhofer(input_path, allow_fallback=True)
    if backend == "fraunhofer-strict":
        return _load_with_fraunhofer(input_path, allow_fallback=False)
    raise CpgLoadError(f"Unsupported backend: {backend}")


def _load_with_fraunhofer(input_path: Path, allow_fallback: bool) -> NormalizedGraph:
    """
    Invoke Fraunhofer CPG exporter as a subprocess and load the normalized JSON output.
    
    Normalization Process:
    1. Subprocess spawns: java -jar exporter.jar --input <input_path> --output <temp.json>
    2. Exporter reads Python source, builds CPG, normalizes to NormalizedGraph JSON
    3. Exporter writes normalized JSON with nodes and edges
       - Nodes: function, call, argument, assignment, return, variable, literal
       - Edges: CALLS, AST, ARGUMENT, RETURN, DFG, DATA_FLOW, REACHES, EOG
       - Each node has backend="fraunhofer" for provenance
    4. Python loader reads and validates JSON
    
    Key Normalization Points:
    - assignment nodes: explicit var = expression tracking
    - return nodes: explicit value flow out of functions
    - call-argument propagation: actual → formal parameter bindings
    - DFG edges: interprocedural dataflow (when available)
    
    Fallback behavior:
    - allow_fallback=True: On subprocess error, fall back to ast-lite with warning
    - allow_fallback=False: Raise error immediately (strict mode for validation)
    """
    exporter = os.environ.get("CRYPTOGRAPH_FRAUNHOFER_EXPORTER")
    if exporter and Path(exporter).exists():
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as handle:
            output_path = Path(handle.name)
        log_path = output_path.with_suffix(".exporter.log")
        try:
            proc = subprocess.run(
                ["java", "-jar", exporter, "--input", str(input_path), "--output", str(output_path)],
                check=False,
                text=True,
                capture_output=True,
            )
            # save exporter stdout/stderr for diagnostics
            try:
                with log_path.open("w", encoding="utf-8") as f:
                    f.write("STDOUT:\n")
                    f.write((proc.stdout or "") + "\n")
                    f.write("STDERR:\n")
                    f.write((proc.stderr or "") + "\n")
            except Exception:
                pass
            if proc.returncode != 0:
                raise subprocess.CalledProcessError(proc.returncode, proc.args, output=proc.stdout, stderr=proc.stderr)
            with output_path.open("r", encoding="utf-8") as graph_file:
                graph = NormalizedGraph.model_validate(json.load(graph_file))
            # run diagnostics to ensure exporter produced expected CPG elements
            try:
                _diagnostic_graph_report(graph, input_path, log_path)
            except Exception:
                pass
            if looks_like_c_cpp(input_path) and _graph_has_no_usable_calls(graph):
                print(
                    "[cryptograph][warning] Fraunhofer exporter produced no usable C/C++ call graph; "
                    "using c-cpp-lite source scanner for OpenSSL/TLS API detection.",
                    file=sys.stderr,
                )
                return build_c_cpp_lite_graph(input_path)
            return graph
        except (subprocess.CalledProcessError, OSError, json.JSONDecodeError) as exc:
            # ensure exporter logs are saved if we captured a proc
            proc = locals().get("proc")
            if proc is not None:
                try:
                    with log_path.open("w", encoding="utf-8") as f:
                        f.write("STDOUT:\n")
                        f.write((proc.stdout or "") + "\n")
                        f.write("STDERR:\n")
                        f.write((proc.stderr or "") + "\n")
                except Exception:
                    pass
            if not allow_fallback:
                detail = _format_exporter_error(exc)
                raise CpgLoadError(f"Fraunhofer CPG exporter failed in strict mode. {detail}") from exc
            print(
                f"[cryptograph] Fraunhofer exporter failed, falling back to ast-lite: {exc}",
                file=sys.stderr,
            )
            # Warn when falling back to ast-lite if repository contains other languages
            if input_path.is_dir():
                other_exts = {".java": "Java", ".c": "C", ".cpp": "C++", ".h": "C/C++ headers", ".js": "JavaScript", ".ts": "TypeScript", ".go": "Go", ".cs": "C#"}
                detected = set()
                for path in input_path.iterdir():
                    if path.is_file():
                        ext = path.suffix.lower()
                        if ext in other_exts:
                            detected.add(other_exts[ext])
                if detected:
                    print(
                        f"[cryptograph][warning] Falling back to ast-lite but detected non-Python files: {', '.join(sorted(detected))}. "
                        "ast-lite will not produce interprocedural CPG/DFG across these languages. "
                        "Consider using the Fraunhofer exporter (Docker) for full multi-language CPGs.",
                        file=sys.stderr,
                    )
            graph = build_ast_lite_graph(input_path)
            graph.backend = "fraunhofer-failed:ast-lite"
            # attach a CBOM node so callers (and LLM labelers) can get a complete bill-of-materials
            try:
                cbom = extract_cbom(input_path)
                cbom_node = GraphNode(id=f"{input_path.as_posix()}:cbom", kind="cbom", name="cbom", file=input_path.as_posix(), properties={"cbom": cbom})
                graph.nodes.append(cbom_node)
            except Exception:
                pass
            try:
                _diagnostic_graph_report(graph, input_path, log_path if log_path.exists() else None)
            except Exception:
                pass
            return graph
        finally:
            output_path.unlink(missing_ok=True)

    if not allow_fallback:
        raise CpgLoadError(
            "Fraunhofer CPG exporter artifact not found. Set CRYPTOGRAPH_FRAUNHOFER_EXPORTER "
            "to the exporter jar path or run inside the Docker image."
        )

    print(
        "[cryptograph] Fraunhofer exporter artifact not found; using ast-lite fallback.",
        file=sys.stderr,
    )
    # Warn when falling back to ast-lite if repository contains other languages
    if input_path.is_dir():
        other_exts = {".java": "Java", ".c": "C", ".cpp": "C++", ".h": "C/C++ headers", ".js": "JavaScript", ".ts": "TypeScript", ".go": "Go", ".cs": "C#"}
        detected = set()
        for path in input_path.iterdir():
            if path.is_file():
                ext = path.suffix.lower()
                if ext in other_exts:
                    detected.add(other_exts[ext])
        if detected:
            print(
                f"[cryptograph][warning] Falling back to ast-lite but detected non-Python files: {', '.join(sorted(detected))}. "
                "ast-lite will not produce interprocedural CPG/DFG across these languages. "
                "Consider using the Fraunhofer exporter (Docker) for full multi-language CPGs.",
                file=sys.stderr,
            )
    graph = build_ast_lite_graph(input_path)
    try:
        _diagnostic_graph_report(graph, input_path, None)
    except Exception:
        pass
    graph.backend = "fraunhofer-fallback:ast-lite"
    try:
        cbom = extract_cbom(input_path)
        cbom_node = GraphNode(id=f"{input_path.as_posix()}:cbom", kind="cbom", name="cbom", file=input_path.as_posix(), properties={"cbom": cbom})
        graph.nodes.append(cbom_node)
    except Exception:
        pass
    return graph


def _graph_has_no_usable_calls(graph: NormalizedGraph) -> bool:
    return not any(node.kind == "call" for node in graph.nodes)


def _looks_like_ruby(input_path: Path) -> bool:
    if input_path.is_file():
        return input_path.suffix.lower() == ".rb"
    if not input_path.is_dir():
        return False
    has_ruby = next(input_path.rglob("*.rb"), None) is not None
    has_python = next(input_path.rglob("*.py"), None) is not None
    return has_ruby and not has_python


def _format_exporter_error(exc: Exception) -> str:
    if isinstance(exc, subprocess.CalledProcessError):
        stderr = (exc.stderr or "").strip()
        stdout = (exc.stdout or "").strip()
        parts = [f"exit_code={exc.returncode}"]
        if stderr:
            parts.append(f"stderr={stderr[-1200:]}")
        if stdout:
            parts.append(f"stdout={stdout[-1200:]}")
        return " ".join(parts)
    return str(exc)


def _diagnostic_graph_report(graph: NormalizedGraph, input_path: Path, exporter_log: Optional[Path]) -> None:
    """Quick diagnostics for a NormalizedGraph: check for dataflow completeness.

    Prints a brief summary to stderr indicating missing node/edge kinds that are
    typically produced by the Fraunhofer exporter for multi-language CPGs.
    """
    node_kinds = {n.kind for n in graph.nodes}
    edge_kinds = {e.kind for e in graph.edges}

    required_node_kinds = {"assignment", "return"}
    required_edge_kinds = {"DFG", "DATA_FLOW", "REACHES", "EOG"}

    missing_nodes = required_node_kinds - node_kinds
    missing_edges = {k for k in required_edge_kinds if k not in edge_kinds}

    if missing_nodes or missing_edges:
        parts = []
        if missing_nodes:
            parts.append(f"missing node kinds: {', '.join(sorted(missing_nodes))}")
        if missing_edges:
            parts.append(f"missing edge kinds: {', '.join(sorted(missing_edges))}")
        sample_counts = f"nodes={len(graph.nodes)} edges={len(graph.edges)} backend={graph.backend}"
        msg = (
            f"[cryptograph][diagnostic] Incomplete CPG detected ({sample_counts}): " + ", ".join(parts)
        )
        if exporter_log:
            msg += f"; exporter log: {exporter_log}"
        msg += (
            ".\nIf you expected a multi-language interprocedural CPG, ensure the Fraunhofer exporter "
            "was run with language parsers enabled or run inside the official Docker image."
        )
        print(msg, file=sys.stderr)
    else:
        print(f"[cryptograph][diagnostic] CPG looks complete: nodes={len(graph.nodes)} edges={len(graph.edges)}", file=sys.stderr)
