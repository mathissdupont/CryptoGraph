from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Any

try:
    import tomllib  # Python 3.11+
except Exception:
    tomllib = None


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _parse_package_json(path: Path) -> Dict[str, List[str]]:
    data = _read_json(path)
    deps = {}
    for k in ("dependencies", "devDependencies", "peerDependencies"):
        if isinstance(data.get(k), dict):
            deps[k] = [f"{name}@{ver}" for name, ver in data[k].items()]
    return deps


def _parse_requirements_txt(path: Path) -> Dict[str, List[str]]:
    lines = [l.strip() for l in path.read_text(encoding="utf-8").splitlines()]
    pkgs = [l for l in lines if l and not l.startswith("#")]
    return {"requirements.txt": pkgs}


def _parse_pyproject(path: Path) -> Dict[str, Any]:
    text = path.read_bytes()
    if tomllib:
        data = tomllib.loads(text)
    else:
        try:
            import toml

            data = toml.loads(text.decode("utf-8"))
        except Exception:
            return {}
    deps = {}
    # PEP 621: [project].dependencies
    project = data.get("project") or {}
    if isinstance(project.get("dependencies"), list):
        deps["project.dependencies"] = project["dependencies"]
    # poetry
    poetry = data.get("tool", {}).get("poetry") if data.get("tool") else None
    if poetry and isinstance(poetry.get("dependencies"), dict):
        deps["poetry.dependencies"] = [f"{n}:{v}" for n, v in poetry["dependencies"].items()]
    return deps


def _parse_go_mod(path: Path) -> Dict[str, List[str]]:
    lines = [l.strip() for l in path.read_text(encoding="utf-8").splitlines()]
    reqs = [l.split()[1] + " " + (l.split()[2] if len(l.split()) > 2 else "") for l in lines if l.startswith("require") or l.startswith("\t")]
    return {"go.mod": reqs}


def _parse_pom_xml(path: Path) -> Dict[str, List[str]]:
    try:
        root = ET.fromstring(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    ns = {k: v for k, v in [("m", root.tag.split("}")[0].strip("{"))] if "}" in root.tag}
    deps = []
    for dep in root.findall(".//dependency"):
        gid = dep.findtext("groupId") or dep.findtext("{*}groupId")
        aid = dep.findtext("artifactId") or dep.findtext("{*}artifactId")
        ver = dep.findtext("version") or dep.findtext("{*}version")
        deps.append(":".join(filter(None, [gid, aid, ver])))
    return {"pom.xml": deps}


def _parse_cargo_toml(path: Path) -> Dict[str, List[str]]:
    text = path.read_text(encoding="utf-8")
    deps = []
    in_deps = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("[dependencies]"):
            in_deps = True
            continue
        if in_deps:
            if s.startswith("["):
                break
            if s and not s.startswith("#"):
                key = s.split("=", 1)[0].strip()
                deps.append(key)
    return {"Cargo.toml": deps}


def extract_cbom(root: Path) -> Dict[str, Any]:
    """Extract a simple CBOM (list of dependencies) from common manifest files.

    This is not a full CPG, but provides a language-agnostic bill-of-materials
    suitable for labeling and quick triage when a full exporter isn't available.
    """
    root = root.resolve()
    manifests = list(root.glob("**/package.json")) + list(root.glob("**/requirements.txt")) + list(root.glob("**/pyproject.toml")) + list(root.glob("**/go.mod")) + list(root.glob("**/pom.xml")) + list(root.glob("**/Cargo.toml"))
    cbom: Dict[str, Any] = {"manifests": [], "components": {}}
    for m in manifests:
        try:
            if m.name == "package.json":
                parsed = _parse_package_json(m)
            elif m.name == "requirements.txt":
                parsed = _parse_requirements_txt(m)
            elif m.name == "pyproject.toml":
                parsed = _parse_pyproject(m)
            elif m.name == "go.mod":
                parsed = _parse_go_mod(m)
            elif m.name == "pom.xml":
                parsed = _parse_pom_xml(m)
            elif m.name == "Cargo.toml":
                parsed = _parse_cargo_toml(m)
            else:
                parsed = {}
        except Exception:
            parsed = {}
        cbom["manifests"].append(str(m.relative_to(root)))
        cbom["components"][str(m.relative_to(root))] = parsed
    return cbom
