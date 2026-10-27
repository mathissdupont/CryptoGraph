"""Reproduce the local Python demo without executing the sample programs."""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def git_output(*args: str) -> str | None:
    try:
        return subprocess.check_output(
            ["git", *args], cwd=ROOT, text=True, stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=ROOT / "output" / "reproduction")
    args = parser.parse_args()
    out = args.out_dir.resolve()
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        parser.error(f"Output directory must be new or empty: {out}")
    out.mkdir(parents=True, exist_ok=True)

    prefix = [sys.executable, "-m", "cryptograph.main"]
    commands = [
        prefix + [
            "scan", "--input", str(ROOT / "samples"), "--backend", "ast-lite",
            "--output", str(out / "cbom.json"), "--report", str(out / "report.html"),
            "--run-dir", str(out),
        ],
        prefix + [
            "graph", "--input", str(ROOT / "samples"), "--backend", "ast-lite",
            "--output", str(out / "graph.json"), "--dot", str(out / "graph.dot"),
            "--html", str(out / "graph.html"),
        ],
    ]
    # Capture before commands so all artifacts refer to the same input snapshot.
    inputs = sorted({
        *ROOT.joinpath("samples").rglob("*.py"),
        *ROOT.joinpath("config").rglob("*.json"),
        *ROOT.joinpath("src", "cryptograph").glob("*.py"),
        Path(__file__).resolve(), ROOT / "pyproject.toml",
    })
    status = git_output("status", "--porcelain", "--untracked-files=normal")
    record = {
        "generated_at": datetime.now(UTC).isoformat(),
        "revision": git_output("rev-parse", "HEAD"),
        "working_tree_dirty": bool(status) if status is not None else None,
        "python": sys.version,
        "platform": platform.platform(),
        "dependencies": {name: version(name) for name in ("cryptograph", "networkx", "pydantic")},
        "commands": commands,
        "inputs_sha256": {
            path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in inputs
        },
        "status": "running",
    }
    record_path = out / "reproduction.json"

    def save() -> None:
        record_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")

    save()
    for command in commands:
        result = subprocess.run(command, cwd=ROOT, check=False)
        if result.returncode:
            record.update(status="failed", failed_command=command, exit_code=result.returncode)
            save()
            return result.returncode

    cbom = json.loads((out / "cbom.json").read_text(encoding="utf-8"))
    record.update(status="completed", backend=cbom["metadata"]["backend"], summary=cbom["summary"])
    save()
    print(f"Reproduction artifacts: {out}")
    print("This demonstration is not an accuracy benchmark.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
