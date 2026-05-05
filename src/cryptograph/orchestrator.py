from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import shutil
import subprocess
import os
import sys
from pathlib import Path

from cryptograph.main import _scan
from cryptograph.utils import load_json, write_json, project_path
from cryptograph.langdetect import detect_language_roots, EXT_LANG_MAP


def _config_language_for(lang: str) -> str:
    """Map detected language IDs to config families.

    Multiple languages intentionally share rule/mapping families.
    """
    aliases = {
        "kotlin": "java",
        "typescript": "javascript",
        "c": "c_cpp",
        "cpp": "c_cpp",
    }
    return aliases.get(lang, lang)


def _language_family_for(lang: str) -> str:
    """Group languages that intentionally share parser/rule inputs."""
    if _config_language_for(lang) == "c_cpp":
        return "c_cpp"
    if _config_language_for(lang) == "javascript":
        return "javascript"
    return lang


def _file_family(path: Path) -> str | None:
    lang = EXT_LANG_MAP.get(path.suffix.lower())
    if not lang:
        return None
    return _language_family_for(lang)


def _prepare_language_input(source_root: Path, job_lang: str, staging_root: Path) -> Path:
    """Create a language-scoped input tree so mixed directories do not cross-contaminate jobs."""
    source_root = source_root.resolve()
    staging_root.mkdir(parents=True, exist_ok=True)
    target_family = _language_family_for(job_lang)
    files = [source_root] if source_root.is_file() else sorted(p for p in source_root.rglob("*") if p.is_file())

    copied = 0
    for path in files:
        if _file_family(path) != target_family:
            continue
        try:
            relative = path.relative_to(source_root.parent if source_root.is_file() else source_root)
        except ValueError:
            relative = Path(path.name)
        destination = staging_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
        copied += 1

    if copied == 0:
        return source_root
    return staging_root


def _dedupe_language_roots(lang_roots: dict[str, list[Path]]) -> dict[str, list[Path]]:
    """Drop duplicate child roots inside each parser/rule family."""
    grouped: dict[str, list[tuple[str, Path]]] = {}
    for lang, roots in lang_roots.items():
        grouped.setdefault(_language_family_for(lang), []).extend((lang, root.resolve()) for root in roots)

    deduped: dict[str, list[Path]] = {}
    for family_items in grouped.values():
        selected: list[tuple[str, Path]] = []
        for lang, root in sorted(family_items, key=lambda item: (len(item[1].parts), str(item[1]))):
            if any(_is_relative_to(root, parent) for _, parent in selected):
                continue
            selected.append((lang, root))
        for lang, root in selected:
            deduped.setdefault(lang, []).append(root)
    return {lang: sorted(roots) for lang, roots in deduped.items()}


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def clone_repo(git_url: str, dest: Path) -> Path:
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    subprocess.check_call(["git", "clone", "--depth", "1", git_url, str(dest)])
    return dest


def find_python_roots(repo_root: Path) -> list[Path]:
    roots: list[Path] = []
    for p in repo_root.rglob("*.py"):
        roots.append(p.parent)
    # dedupe and prefer top-level folders
    roots = sorted({r.resolve() for r in roots})
    return roots


def scan_repo(
    path_or_url: str,
    output_dir: Path,
    backend: str = "fraunhofer",
    build_exporter: bool = False,
    max_workers: int | None = None,
) -> dict:
    repo_path = Path(path_or_url)
    if path_or_url.startswith("http://") or path_or_url.startswith("https://") or path_or_url.endswith(".git"):
        repo_path = clone_repo(path_or_url, output_dir / "repo")

    lang_roots = detect_language_roots(repo_path)
    # if nothing detected, fallback to whole repo as generic
    if not lang_roots:
        lang_roots = {"unknown": [repo_path]}
    lang_roots = _dedupe_language_roots(lang_roots)

    if build_exporter and not os.environ.get("CRYPTOGRAPH_FRAUNHOFER_EXPORTER"):
        try:
            script = project_path("scripts", "build_fraunhofer_exporter.sh")
            enabled_languages = ",".join(sorted(lang for lang in lang_roots.keys() if lang != "unknown")) or "python,java,go"
            subprocess.run([str(script), str(output_dir / "cpg-build"), enabled_languages], check=True)
        except subprocess.CalledProcessError:
            print("Warning: building Fraunhofer exporter failed; continuing without exporter.")

    jobs: list[dict[str, object]] = []

    index = 0
    for lang, roots in lang_roots.items():
        for root in roots:
            detected = _config_language_for(lang)
            config_language = detected
            jobs.append(
                {
                    "index": index,
                    "lang": lang,
                    "root": root,
                    "detected": detected,
                    "mappings": project_path("config", f"api_mappings.{config_language}.json") if os.path.exists(project_path("config", f"api_mappings.{config_language}.json")) else project_path("config", "api_mappings.json"),
                    "rules": project_path("config", f"rules_v2.{config_language}.json") if os.path.exists(project_path("config", f"rules_v2.{config_language}.json")) else project_path("config", "rules_v2.json"),
                }
            )
            index += 1

    def run_job(job: dict[str, object]) -> tuple[int, dict]:
        root = Path(job["root"])
        job_run_dir = output_dir / f"run-{job['lang']}-{root.name}-{job['index']}"
        out_path = job_run_dir / f"cbom-{job['lang']}-{root.name}.json"
        scan_input = _prepare_language_input(root, str(job["lang"]), job_run_dir / "input")

        class Args:
            pass

        a = Args()
        a.input = scan_input
        a.output = out_path
        a.backend = backend
        a.mappings = Path(job["mappings"])
        a.rules = Path(job["rules"])
        a.report = None
        a.run_dir = job_run_dir

        _scan(a)
        cbom = load_json(out_path)
        cbom.setdefault("metadata", {})["detected_language"] = str(job["detected"])
        cbom["metadata"]["source_language"] = str(job["detected"])
        cbom.setdefault("analysis", {}).setdefault("scope", {})["language"] = str(job["detected"])
        return int(job["index"]), cbom

    all_cboms: list[dict] = []
    results: dict[int, dict] = {}
    errors: list[dict[str, object]] = []
    if jobs:
        worker_count = max_workers if max_workers is not None else (os.cpu_count() or 1)
        worker_count = max(1, min(worker_count, len(jobs)))

        if worker_count == 1:
            for job in jobs:
                try:
                    index, cbom = run_job(job)
                    results[index] = cbom
                except Exception as exc:
                    errors.append(_job_error(job, exc))
                    print(_job_warning(job, exc), file=sys.stderr)
        else:
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                futures = {executor.submit(run_job, job): job for job in jobs}
                for future in as_completed(futures):
                    job = futures[future]
                    try:
                        index, cbom = future.result()
                        results[index] = cbom
                    except Exception as exc:
                        errors.append(_job_error(job, exc))
                        print(_job_warning(job, exc), file=sys.stderr)

        for index in sorted(results):
            all_cboms.append(results[index])

    merged = {"cboms": all_cboms, "errors": errors, "summary": {"jobs": len(jobs), "succeeded": len(all_cboms), "failed": len(errors)}}
    write_json(output_dir / "merged-cboms.json", merged)
    return merged


def _job_error(job: dict[str, object], exc: Exception) -> dict[str, object]:
    return {
        "index": job.get("index"),
        "language": job.get("lang"),
        "detected_language": job.get("detected"),
        "root": str(job.get("root")),
        "mappings": str(job.get("mappings")),
        "rules": str(job.get("rules")),
        "error": f"{type(exc).__name__}: {exc}",
    }


def _job_warning(job: dict[str, object], exc: Exception) -> str:
    return (
        "[cryptograph][scan-repo][warning] "
        f"job={job.get('index')} lang={job.get('lang')} root={job.get('root')} failed: "
        f"{type(exc).__name__}: {exc}"
    )


def export_cbom_to_jsonl(merged_cboms: dict, out_file: Path) -> int:
    """Simple exporter that flattens cryptographic_assets into JSONL rows.

    Each line: {"asset_id": ..., "input": {...}, "labels": {...}}
    Labels are left empty for LLM labeling stage.
    """
    import json

    count = 0
    with out_file.open("w", encoding="utf-8") as fh:
        for cbom in merged_cboms.get("cboms", []):
            metadata = cbom.get("metadata", {}) if isinstance(cbom.get("metadata", {}), dict) else {}
            for asset in cbom.get("cryptographic_assets", []):
                row = {
                    "asset_id": asset.get("asset_id"),
                    "task": "crypto_asset_labeling",
                    "input": {
                        "metadata": {
                            "detected_language": metadata.get("detected_language"),
                            "backend": metadata.get("backend"),
                            "source": metadata.get("source"),
                            "run_id": metadata.get("run_id"),
                        },
                        "crypto_metadata": asset.get("crypto_metadata"),
                        "usage": asset.get("usage"),
                        "context": {
                            "file": asset.get("context", {}).get("file"),
                            "function": asset.get("context", {}).get("function"),
                            "call_chain_len": len(asset.get("context", {}).get("call_chain", []) or []),
                        },
                        "flow": asset.get("flow"),
                        "control": asset.get("control"),
                        "graph_context": asset.get("graph_context"),
                        "rules": asset.get("rules"),
                        "evidence_summary": asset.get("evidence", {}).get("summary"),
                    },
                    "label_schema": {
                        "is_true_positive": "bool",
                        "asset_role": ["primary_asset", "supporting_artifact", "not_crypto"],
                        "algorithm": "string",
                        "primitive": "string",
                        "operation": "string",
                        "risk_level": ["info", "low", "medium", "high", "critical"],
                        "misuse_categories": "list[string]",
                        "requires_pqc_migration": "bool",
                        "confidence": "float 0..1",
                        "rationale": "short string",
                    },
                    "labels": {
                        "is_true_positive": None,
                        "asset_role": None,
                        "algorithm": None,
                        "primitive": None,
                        "operation": None,
                        "risk_level": None,
                        "misuse_categories": [],
                        "requires_pqc_migration": None,
                        "confidence": None,
                        "rationale": None,
                    },
                }
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
                count += 1
    return count
