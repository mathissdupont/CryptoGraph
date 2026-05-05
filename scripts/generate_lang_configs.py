"""Generate per-language api_mappings and rules from templates.

Usage:
    python scripts/generate_lang_configs.py java javascript go

This will create `config/api_mappings.<lang>.json` and `config/rules_v2.<lang>.json` files.
"""
from pathlib import Path
import sys
import json

TEMPLATES = Path(__file__).resolve().parents[1] / "config" / "templates"
OUT_DIR = Path(__file__).resolve().parents[1] / "config"


def render_template(path: Path, language: str) -> dict:
    text = path.read_text(encoding="utf-8")
    text = text.replace("{{language}}", language)
    return json.loads(text)


def main(langs: list[str]):
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    api_t = TEMPLATES / "api_mappings.template.json"
    rules_t = TEMPLATES / "rules.template.json"
    for lang in langs:
        api = render_template(api_t, lang)
        rules = render_template(rules_t, lang)
        api_path = OUT_DIR / f"api_mappings.{lang}.json"
        rules_path = OUT_DIR / f"rules_v2.{lang}.json"
        api_path.write_text(json.dumps(api, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        rules_path.write_text(json.dumps(rules, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"Wrote {api_path} and {rules_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: generate_lang_configs.py <lang> [<lang> ...]")
        raise SystemExit(1)
    main(sys.argv[1:])
