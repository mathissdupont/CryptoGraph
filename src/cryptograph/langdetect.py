from __future__ import annotations

from pathlib import Path
from typing import Dict, List

# Map common file extensions to language labels used by CPG/backends
EXT_LANG_MAP = {
    ".py": "python",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".go": "go",
    ".rs": "rust",
    ".rb": "ruby",
    ".cs": "csharp",
    ".php": "php",
    ".scala": "scala",
    ".swift": "swift",
}


def detect_language_roots(repo_root: Path) -> Dict[str, List[Path]]:
    """Scan the repo tree and group directories by detected language.

    Returns a mapping language -> list of directory roots that contain that language.
    """
    lang_dirs: Dict[str, set[Path]] = {}
    for p in repo_root.rglob("*"):
        if not p.is_file():
            continue
        lang = EXT_LANG_MAP.get(p.suffix.lower())
        if not lang:
            continue
        lang_dirs.setdefault(lang, set()).add(p.parent.resolve())

    # Convert sets to sorted lists
    return {lang: sorted(list(dirs)) for lang, dirs in lang_dirs.items()}
