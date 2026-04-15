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
    input_path = input_path.resolve()
    if backend == "ast-lite":
        return build_ast_lite_graph(input_path)
    if backend == "fraunhofer":
        return _load_with_fraunhofer(input_path, allow_fallback=True)
    if backend == "fraunhofer-strict":
        return _load_with_fraunhofer(input_path, allow_fallback=False)
    raise CpgLoadError(f"Unsupported backend: {backend}")


def _load_with_fraunhofer(input_path: Path, allow_fallback: bool) -> NormalizedGraph:
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
