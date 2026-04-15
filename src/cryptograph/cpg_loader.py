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

from cryptograph.ast_lite import build_ast_lite_graph
from cryptograph.models import NormalizedGraph


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
    if backend == "ast-lite":
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
        try:
            subprocess.run(
                ["java", "-jar", exporter, "--input", str(input_path), "--output", str(output_path)],
                check=True,
                text=True,
                capture_output=True,
            )
            with output_path.open("r", encoding="utf-8") as graph_file:
                return NormalizedGraph.model_validate(json.load(graph_file))
        except (subprocess.CalledProcessError, OSError, json.JSONDecodeError) as exc:
            if not allow_fallback:
                detail = _format_exporter_error(exc)
                raise CpgLoadError(f"Fraunhofer CPG exporter failed in strict mode. {detail}") from exc
            print(
                f"[cryptograph] Fraunhofer exporter failed, falling back to ast-lite: {exc}",
                file=sys.stderr,
            )
            graph = build_ast_lite_graph(input_path)
            graph.backend = "fraunhofer-failed:ast-lite"
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
    graph = build_ast_lite_graph(input_path)
    graph.backend = "fraunhofer-fallback:ast-lite"
    return graph


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
