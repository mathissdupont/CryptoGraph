"""Unit fixtures exercise scoring mechanics; they are not real review records."""
import copy
import hashlib
import json

import pytest

from cryptograph.cpg_loader import load_graph
from cryptograph.key_origin import MODEL, analyze_key_origins
from cryptograph.research_eval import ReviewPending, score_provisional, score_reviewed
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


def test_failed_scan_is_neither_missing_detection_nor_abstention(data):
    root,annotations,observations=data
    observations['cases'][0].update(scan_status='failed',evidence_policy=[])
    group=score_reviewed(annotations,observations,root)['by_split']['development']
    assert group['failed_scans']==1 and group['missing_or_ambiguous']==0 and group['abstained']==0


def test_project_candidate_review_cannot_be_replaced_by_origin_labels_alone(data):
    root,annotations,observations=data
    annotations['cases'][0]['candidate_status']='nominal_import_candidate_needs_review'
    with pytest.raises(ReviewPending):
        score_reviewed(annotations,observations,root)


def test_explicit_author_review_is_not_declared_independent(data):
    root,annotations,observations=data
    annotations['cases'][0]['independent_review']['reviewer_role']='project_author'
    with pytest.raises(ReviewPending):
        score_reviewed(annotations,observations,root)


def test_project_specific_graph_contexts_are_required_when_an_index_is_supplied(data):
    root,annotations,observations=data
    annotations['cases'][0]['project']='example'
    context=load_graph(root/'example.py','ast-lite')
    result=score_reviewed(annotations,observations,root,{'example':context})
    assert result['by_split']['development']['claims_with_structural_errors']==0
    with pytest.raises(ValueError,match='Missing graph context'):
        score_reviewed(annotations,observations,root,{})


@pytest.mark.parametrize("origin,reference_complete,expected", [
    ("literal", True, False), ("csprng_api", True, True), ("literal", False, None),
])
def test_partial_claims_are_judged_only_against_complete_reference_sets(data, origin, reference_complete, expected):
    root, annotations, observations = data
    claim = observations["cases"][0]["evidence_policy"][0]["claim"]
    claim.update(origins=[origin], status="partial", origin_set_complete=False, modality="may", unresolved_reasons=["fixture_unknown_branch"])
    if not reference_complete:
        annotations["cases"][0]["independent_review"]["reviewed_reference"].update(status="partial", origin_set_complete=False, modality="may")
    result = score_reviewed(annotations, observations, root)
    assert result["cases"][0]["partial_assertion_error"] is expected
    group = result["by_split"]["development"]
    assert group["resolved"] == 0 and group["partial"] == 1
    assert group["partial_assertions_judgeable"] == int(reference_complete)
    assert group["partial_assertion_error_rate"] == (float(expected) if expected is not None else None)


def test_abstention_is_not_a_judgeable_partial_assertion(data):
    root, annotations, observations = data
    claim = observations["cases"][0]["evidence_policy"][0]["claim"]
    claim.update(origins=[], status="abstained", origin_set_complete=False, modality="unknown", unresolved_reasons=["fixture"])
    group = score_reviewed(annotations, observations, root)["by_split"]["development"]
    assert group["partial_assertions_judgeable"] == 0 and group["partial_assertion_error_rate"] is None


@pytest.mark.parametrize('reference_status', ['partial', 'abstained'])
def test_incomplete_reference_cannot_establish_a_resolved_claim_is_false(data, reference_status):
    root,annotations,observations=data
    reference=annotations['cases'][0]['independent_review']['reviewed_reference']
    reference.update(status=reference_status,origins=['literal'] if reference_status=='partial' else [],
                     origin_set_complete=False,modality='may' if reference_status=='partial' else 'unknown')
    result=score_reviewed(annotations,observations,root)
    group=result['by_split']['development']
    assert group['resolved']==1 and group['resolved_semantics_judgeable']==0
    assert group['semantic_error_rate_among_resolved'] is None
    assert result['cases'][0]['semantic_error'] is None
    assert result['cases'][0]['reference_resolution_mismatch'] is True


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


def provisional_data(data):
    root, annotations, observations = data
    entry = annotations["cases"][0]
    proposal = {field: copy.deepcopy(entry[field]) for field in ("case_id", "source_sha256", "target", "target_api")}
    proposal.update(proposed_reference=entry["independent_review"]["reviewed_reference"],
                    source_inspection_rationale="Synthetic source-inspection fixture, not a real review.")
    entry["independent_review"] = {"status": "pending", "reviewer": None, "reviewed_reference": None}
    proposals = {"analysis_model": MODEL,
                 "status": "assistant_source_inspection_proposals_not_independent_ground_truth", "cases": [proposal]}
    return root, annotations, proposals, observations


def test_provisional_mode_does_not_approve_reviews_or_claim_accuracy(data):
    root, annotations, proposals, observations = provisional_data(data)
    original = copy.deepcopy(annotations)
    result = score_provisional(annotations, proposals, observations, root)
    assert annotations == original
    assert result["status"] == "provisional_development_agreement_only"
    assert result["by_split"]["development"]["proposed_reference_disagreements_among_resolved"] == 0
    assert "semantic_error" not in json.dumps(result)
    with pytest.raises(ReviewPending):
        score_reviewed(annotations, observations, root)


@pytest.mark.parametrize("mutation", ["held_out", "stale_source", "missing_id", "duplicate_id", "missing_rationale", "unmarked_proposals"])
def test_provisional_mode_rejects_misleading_or_mismatched_references(data, mutation):
    root, annotations, proposals, observations = provisional_data(data)
    if mutation == "held_out":
        annotations["cases"][0]["split"] = "held_out"
    elif mutation == "stale_source":
        proposals["cases"][0]["source_sha256"] = "stale"
    elif mutation == "missing_id":
        proposals["cases"] = []
    elif mutation == "duplicate_id":
        proposals["cases"].append(copy.deepcopy(proposals["cases"][0]))
    elif mutation == "missing_rationale":
        proposals["cases"][0]["source_inspection_rationale"] = ""
    else:
        proposals["status"] = "ground_truth"
    with pytest.raises(ValueError):
        score_provisional(annotations, proposals, observations, root)


def test_provisional_disagreement_and_abstention_remain_distinct(data):
    root, annotations, proposals, observations = provisional_data(data)
    claim = observations["cases"][0]["evidence_policy"][0]["claim"]
    claim["origins"] = ["csprng_api"]
    group = score_provisional(annotations, proposals, observations, root)["by_split"]["development"]
    assert group["proposed_reference_disagreements_among_resolved"] == 1
    claim.update(origins=[], status="abstained", origin_set_complete=False, modality="unknown", unresolved_reasons=["fixture"])
    group = score_provisional(annotations, proposals, observations, root)["by_split"]["development"]
    assert group["resolved_coverage"] == 0
    assert group["proposed_reference_disagreement_rate_among_resolved"] is None


def test_corpus_inventory_proposals_and_sources_match():
    root = project_path("research", "python-key-origin")
    packet = json.loads((root / "review-template.json").read_text())
    proposals = json.loads((root / "review-proposals.json").read_text())
    manifest = json.loads((root / "cases.json").read_text())
    entries = {entry["case_id"]: entry for entry in packet["cases"]}
    assert len(entries) == len(packet["cases"]) == len(proposals["cases"]) == len(manifest["cases"]) == 27
    assert set(entries) == {entry["id"] for entry in manifest["cases"]}
    for proposal in proposals["cases"]:
        entry = entries[proposal["case_id"]]
        for field in ("source_sha256", "target", "target_api"):
            assert proposal[field] == entry[field]
        assert entry["independent_review"]["status"] == "pending"
        assert entry["independent_review"]["reviewed_reference"] is None
        # This checks candidate-site identity only, not origin-label correctness.
        claims = analyze_key_origins(root / entry["source"])
        assert len(claims) == 1
        assert claims[0].target.model_dump() == entry["target"]
        assert claims[0].target_api == entry["target_api"]
