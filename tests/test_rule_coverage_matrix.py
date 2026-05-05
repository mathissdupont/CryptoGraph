from __future__ import annotations

import json

from cryptograph.utils import project_path


TARGET_LANGUAGES = [
    "java",
    "javascript",
    "go",
    "c_cpp",
    "ruby",
    "python",
    "typescript",
    "kotlin",
    "csharp",
]


def _load_rules(lang: str) -> list[dict]:
    path = project_path("config", f"rules_v2.{lang}.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("rules", [])


def _has_predicate(rules: list[dict], predicate: str) -> bool:
    return any(predicate in (rule.get("match") or {}) for rule in rules)


def _has_pqc_rule(rules: list[dict]) -> bool:
    return any("PQC" in str(rule.get("id", "")) for rule in rules)


def _has_good_practice_rule(rules: list[dict]) -> bool:
    return any(str(rule.get("risk", "")).lower() in {"low", "info"} for rule in rules)


def test_rule_matrix_has_minimum_parity_across_languages() -> None:
    for lang in TARGET_LANGUAGES:
        rules = _load_rules(lang)

        assert len(rules) >= 10, f"{lang} should have at least 10 rules"
        assert _has_predicate(rules, "mode_in"), f"{lang} missing mode_in coverage"
        assert _has_predicate(rules, "algorithm_in"), f"{lang} missing algorithm_in coverage"
        assert _has_predicate(rules, "key_size_less_than"), f"{lang} missing key_size_less_than coverage"
        assert _has_good_practice_rule(rules), f"{lang} missing low/info guidance rule"
        assert _has_pqc_rule(rules), f"{lang} missing PQC migration rule"
