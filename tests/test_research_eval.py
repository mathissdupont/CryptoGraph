"""Unit fixtures exercise scoring mechanics; they are not real review records."""
import copy
import hashlib
import json

import pytest

from cryptograph.cpg_loader import load_graph
from cryptograph.key_origin import MODEL, analyze_key_origins
from cryptograph.research_eval import ReviewPending, score_reviewed
from cryptograph.utils import project_path


@pytest.fixture
def data(tmp_path):
    source = tmp_path / "example.py"
    source.write_text('from Crypto.Cipher import AES\ndef f():\n    return AES.new(b"fixed", AES.MODE_ECB)\n', encoding="utf-8")
    claim = analyze_key_origins(source, load_graph(source, "ast-lite"))[0]
    reference = {"status": "resolved", "origins": ["literal"], "origin_set_complete": True,
                 "modality": "must", "immediate_boundary": "literal"}
    annotations = {"analysis_model": MODEL, "cases": [{
        "case_id": "literal", "source": source.name, "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "split": "development", "scenario_family": "literal_family", "target_api": claim.target_api,
        "target": claim.target.model_dump(),
        "independent_review": {"status": "approved", "reviewer": "unit-fixture-not-real-review", "reviewed_reference": reference},
    }]}
    observations = {"analysis_model": MODEL, "policy": "both", "cases": [{
        "case_id": "literal", "evidence_policy": [{"claim": claim.model_dump(), "structural_errors": ["do-not-trust-this-cache"]}],
    }]}
    return tmp_path, annotations, observations


def test_pending_review_blocks_metrics_even_with_proposed_reference(data):
    root, annotations, observations = data
    review = annotations["cases"][0]["independent_review"]
    annotations["cases"][0]["proposed_reference"] = review["reviewed_reference"]
    review.update(status="pending", reviewer=None, reviewed_reference=None)
    with pytest.raises(ReviewPending):
        score_reviewed(annotations, observations, root)


def test_scores_recorded_review_and_recomputes_structural_checks(data):
    root, annotations, observations = data
    result = score_reviewed(annotations, observations, root)
    group = result["by_split"]["development"]
    assert group["resolved"] == 1 and group["semantic_errors_among_resolved"] == 0
    assert group["claims_with_structural_errors"] == 0
    assert result["review_independence"] == "declared_by_annotation_record_not_verified_by_software"


def test_wrong_conclusion_and_valid_evidence_shape_are_distinct(data):
    root, annotations, observations = data
    observations["cases"][0]["evidence_policy"][0]["claim"]["origins"] = ["csprng_api"]
    result = score_reviewed(annotations, observations, root)["by_split"]["development"]
    assert result["semantic_errors_among_resolved"] == 1
    assert result["claims_with_structural_errors"] == 0


def test_always_abstain_has_zero_coverage_and_undefined_error_rate(data):
    root, annotations, observations = data
    claim = observations["cases"][0]["evidence_policy"][0]["claim"]
    claim.update(origins=[], status="abstained", origin_set_complete=False, modality="unknown", unresolved_reasons=["fixture"])
    result = score_reviewed(annotations, observations, root)["by_split"]["development"]
    assert result["resolved_coverage"] == 0
    assert result["semantic_error_rate_among_resolved"] is None


def test_missing_claim_is_not_counted_as_abstention(data):
    root, annotations, observations = data
    observations["cases"][0]["evidence_policy"] = []
    group = score_reviewed(annotations, observations, root)["by_split"]["development"]
    assert group["missing_or_ambiguous"] == 1 and group["abstained"] == 0


def test_source_snapshot_mismatch_blocks_scoring(data):
    root, annotations, observations = data
    (root / "example.py").write_text("# changed\n", encoding="utf-8")
    with pytest.raises(ValueError, match="source changed"):
        score_reviewed(annotations, observations, root)


def test_family_leakage_is_rejected(data):
    root, annotations, observations = data
    entry = copy.deepcopy(annotations["cases"][0])
    entry.update(case_id="copy", source="copy.py", split="held_out")
    annotations["cases"].append(entry)
    case = copy.deepcopy(observations["cases"][0])
    case["case_id"] = "copy"
    observations["cases"].append(case)
    with pytest.raises(ValueError, match="leakage"):
        score_reviewed(annotations, observations, root)


def test_duplicate_operation_cannot_inflate_denominator(data):
    root, annotations, observations = data
    entry = copy.deepcopy(annotations["cases"][0])
    entry["case_id"] = "copy"
    annotations["cases"].append(entry)
    case = copy.deepcopy(observations["cases"][0])
    case["case_id"] = "copy"
    observations["cases"].append(case)
    with pytest.raises(ValueError, match="more than once"):
        score_reviewed(annotations, observations, root)


def test_review_packet_sources_are_frozen_and_remain_development_cases():
    root = project_path("research", "python-key-origin")
    packet = json.loads((root / "review-template.json").read_text(encoding="utf-8"))
    for case in packet["cases"]:
        raw = (root / case["source"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == case["source_sha256"]
        assert b"\r\n" not in raw
        assert case["split"] == "development"
