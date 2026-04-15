from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=False)
        handle.write("\n")


def project_path(*parts: str) -> Path:
    return Path(__file__).resolve().parents[2].joinpath(*parts)


def new_run_dir(base: Path | None = None) -> Path:
    base_dir = base or project_path("output")
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    run_dir = base_dir / f"run-{stamp}-{uuid4().hex[:8]}"
    run_dir.mkdir(parents=True, exist_ok=False)
    return run_dir


def path_in_run_dir(path: Path | None, run_dir: Path) -> Path | None:
    if path is None:
        return None
    output_root = project_path("output").resolve()
    resolved_parent = path.parent.resolve()
    if resolved_parent == output_root:
        return run_dir / path.name
    return path


def as_posix_relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()
