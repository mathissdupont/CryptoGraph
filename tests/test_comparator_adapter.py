"""Matching contract checks; these are not comparator performance tests."""
import runpy
from pathlib import Path

import pytest


matches_target = runpy.run_path(str(Path(__file__).parents[1] / "scripts/observe-pqcensus.py"))["matches_target"]


@pytest.mark.parametrize("difference", [None, "file", "start_column", "end_column", "start_line", "end_line"])
def test_comparator_matching_requires_the_exact_source_span(difference):
    target = {"file": "example.py", "line": 4, "column": 0, "end_line": 4, "end_column": 30}
    finding = {"source": {"path": "example.py", "span": {
        "start_line": 4, "start_column": 0, "end_line": 4, "end_column": 30}}}
    if difference == "file":
        finding["source"]["path"] = "other/example.py"
    elif difference:
        finding["source"]["span"][difference] += 1
    assert matches_target(finding, target) is (difference is None)


def test_missing_end_span_is_not_a_verified_site_match():
    target = {"file": "example.py", "line": 4, "column": 0, "end_line": 4, "end_column": 30}
    finding = {"source": {"path": "example.py", "span": {"start_line": 4, "start_column": 0}}}
    assert not matches_target(finding, target)
