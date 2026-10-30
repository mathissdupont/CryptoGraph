"""Separate reviewed diagnostics from explicitly provisional development checks."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError, model_validator

from cryptograph.key_origin import MODEL, KeyOriginClaim, audit_claim_structure
from cryptograph.models import NormalizedGraph


class ReviewPending(ValueError):
    pass


class OriginReference(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["resolved", "partial", "abstained"]
    origins: list[Literal["literal", "csprng_api", "external_configuration"]]
    origin_set_complete: bool
    modality: Literal["must", "may", "unknown"]
    immediate_boundary: str

    @model_validator(mode="after")
    def consistent(self):
        if len(self.origins) != len(set(self.origins)):
            raise ValueError("Duplicate origin category")
        expected_status = "resolved" if self.origins and self.origin_set_complete else "partial" if self.origins else "abstained"
        expected_modality = "must" if expected_status == "resolved" and len(self.origins) == 1 else "may" if self.origins else "unknown"
        if self.status != expected_status or self.modality != expected_modality:
            raise ValueError("Inconsistent reference status/modality")
        if not self.origins and self.origin_set_complete:
            raise ValueError("An unresolved reference cannot assert completeness")
        return self


def score_reviewed(annotations: dict, observations: dict, source_root: Path, graph: NormalizedGraph | dict[str, NormalizedGraph] | None = None) -> dict:
    """Compute diagnostics only after a declared independent review is recorded.

    The gate checks the review record's shape, not the reviewer's identity or
    actual independence. Development-case metrics remain development diagnostics
    even after review; they do not become held-out research results.
    """
    return _score(annotations, observations, source_root, graph)


def score_provisional(annotations: dict, proposals: dict, observations: dict,
                      source_root: Path, graph: NormalizedGraph | dict[str, NormalizedGraph] | None = None) -> dict:
    """Opt-in agreement checks against assistant proposals, on development only.

    This does not approve review records. Proposal files have no independent
    authority, and agreement is not a measurement of research accuracy.
    """
    if proposals.get("analysis_model") != MODEL or proposals.get("status") != "assistant_source_inspection_proposals_not_independent_ground_truth":
        raise ValueError("Expected explicitly provisional source-inspection proposals")
    entries = annotations["cases"]
    if any(entry["split"] != "development" for entry in entries):
        raise ValueError("Provisional references are restricted to development cases")
    proposal_ids = [entry["case_id"] for entry in proposals["cases"]]
    if len(set(proposal_ids)) != len(proposal_ids) or set(proposal_ids) != {entry["case_id"] for entry in entries}:
        raise ValueError("Proposal and annotation case identities must match exactly")
    references = {}
    by_id = {entry["case_id"]: entry for entry in entries}
    for entry in proposals["cases"]:
        if not entry.get("source_inspection_rationale", "").strip():
            raise ValueError("Every provisional reference needs a source-inspection rationale")
        if any(entry.get(field) != by_id[entry["case_id"]][field] for field in ("source_sha256", "target", "target_api")):
            raise ValueError("Provisional proposal/source target snapshot mismatch")
        references[entry["case_id"]] = entry["proposed_reference"]
    result = _score(annotations, observations, source_root, graph, references)
    result.update(status="provisional_development_agreement_only",
                  review_independence="none_assistant_source_inspection_proposals",
                  scope="Development checks against unreviewed proposals; not accuracy, ground truth or held-out evidence.")
    # Avoid presenting agreement with the model's own proposals as semantic truth.
    for group in result["by_split"].values():
        group["proposed_reference_disagreements_among_resolved"] = group.pop("semantic_errors_among_resolved")
        group["proposed_reference_disagreement_rate_among_resolved"] = group.pop("semantic_error_rate_among_resolved")
        group["proposed_boundary_disagreements"] = group.pop("boundary_errors")
        group["resolved_assertions_judgeable_against_proposal"] = group.pop("resolved_semantics_judgeable")
        group["partial_assertions_judgeable_against_proposal"] = group.pop("partial_assertions_judgeable")
        group["partial_assertion_proposal_disagreements"] = group.pop("partial_assertion_errors")
        group["partial_assertion_proposal_disagreement_rate"] = group.pop("partial_assertion_error_rate")
    for row in result["cases"]:
        row["proposed_reference_disagreement"] = row.pop("semantic_error")
        if "boundary_error" in row:
            row["proposed_boundary_disagreement"] = row.pop("boundary_error")
        if "partial_assertion_error" in row:
            row["partial_assertion_proposal_disagreement"] = row.pop("partial_assertion_error")
    return result


def _score(annotations, observations, source_root, graph, provisional_references=None):
    if annotations.get("analysis_model") != MODEL or observations.get("analysis_model") != MODEL:
        raise ValueError("Analysis model mismatch")
    if observations.get("policy") not in {"both", "evidence", "direct"}:
        raise ValueError("Evidence-policy observations are required")
    entries = annotations["cases"]
    if not entries:
        raise ValueError("The annotation corpus is empty")
    ids = [entry["case_id"] for entry in entries]
    observed_ids = [case["case_id"] for case in observations["cases"]]
    if len(ids) != len(set(ids)) or len(observed_ids) != len(set(observed_ids)) or set(ids) != set(observed_ids):
        raise ValueError("Annotation and observation case identities must match exactly")
    family_splits = {}
    sites = set()
    for entry in entries:
        family_splits.setdefault(entry["scenario_family"], set()).add(entry["split"])
        target = entry["target"]
        site = (entry["source"], entry["source_sha256"], entry["target_api"], target["line"], target["column"])
        if site in sites:
            raise ValueError("A source operation is annotated more than once")
        sites.add(site)
    if any(len(splits) != 1 for splits in family_splits.values()):
        raise ValueError("Scenario family leakage across splits")
    pending = [entry["case_id"] for entry in entries if
        entry.get("independent_review", {}).get("status") != "approved"
        or not entry.get("independent_review", {}).get("reviewer")
        or not entry.get("independent_review", {}).get("reviewed_reference")
        or entry.get('independent_review', {}).get('reviewer_role') in {'author','project_author','assistant','model'}
        or (entry.get('candidate_status') and (entry.get('independent_review', {}).get('candidate_verified') is not True
                                              or entry.get('independent_review', {}).get('reviewer_role') != 'independent'))]
    if pending and provisional_references is None:
        raise ReviewPending("Independent review is pending for: " + ", ".join(pending))
    observed = {case["case_id"]: case for case in observations["cases"]}
    rows = []
    for entry in entries:
        path = (source_root / entry["source"]).resolve()
        if not path.is_relative_to(source_root.resolve()):
            raise ValueError("Annotation source is outside the corpus")
        if hashlib.sha256(path.read_bytes()).hexdigest() != entry["source_sha256"]:
            raise ValueError(f"Reference source changed: {entry['case_id']}")
        payload = (entry["independent_review"]["reviewed_reference"] if provisional_references is None
                   else provisional_references[entry["case_id"]])
        reference = OriginReference.model_validate(payload)
        candidates = []
        for item in observed[entry["case_id"]].get("evidence_policy", []):
            payload = item.get("claim", {})
            if payload.get("target") == entry["target"] and payload.get("target_api") == entry["target_api"]:
                candidates.append(payload)
        row = {"case_id": entry["case_id"], "split": entry["split"], "scenario_family": entry["scenario_family"]}
        if observed[entry['case_id']].get('scan_status') == 'failed':
            row.update(outcome='scan_failed', semantic_error=None, structural_errors=[])
        elif len(candidates) != 1:
            row.update(outcome="missing_claim" if not candidates else "ambiguous_claim", semantic_error=None, structural_errors=[])
        else:
            try:
                claim = KeyOriginClaim.model_validate(candidates[0])
            except ValidationError:
                row.update(outcome="invalid_claim_contract", semantic_error=None, structural_errors=["invalid_claim_contract"])
                rows.append(row)
                continue
            if claim.source_sha256 != entry["source_sha256"]:
                raise ValueError(f"Observation/reference source mismatch: {entry['case_id']}")
            context = graph
            if isinstance(graph, dict):
                if entry.get('project') not in graph:
                    raise ValueError('Missing graph context for annotated project')
                context = graph[entry['project']]
            structural_errors = audit_claim_structure(claim, path, context)
            semantic_error = None
            partial_error = None
            partial_comparison = "not_partial"
            if claim.status == "resolved" and reference.origin_set_complete:
                semantic_error = (
                    sorted(claim.origins) != sorted(reference.origins)
                    or claim.modality != reference.modality
                )
            if claim.status == "partial":
                if reference.origin_set_complete:
                    partial_error = not set(claim.origins) <= set(reference.origins)
                    partial_comparison = "outside_complete_reference" if partial_error else "within_complete_reference"
                else:
                    partial_comparison = "indeterminate_incomplete_reference"
            row.update(outcome=claim.status, semantic_error=semantic_error,
                       reference_resolution_mismatch=claim.status == 'resolved' and not reference.origin_set_complete,
                       partial_assertion_error=partial_error, partial_assertion_comparison=partial_comparison,
                       boundary_error=claim.immediate_boundary != reference.immediate_boundary,
                       structural_errors=structural_errors)
        rows.append(row)

    # Keep different splits separate; development data must not be pooled into
    # an apparent held-out score. No uncertainty interval is implied here.
    groups = {}
    for split in sorted({row["split"] for row in rows}):
        selected = [row for row in rows if row["split"] == split]
        answered = [row for row in selected if row["outcome"] == "resolved"]
        judgeable_answered = [row for row in answered if row['semantic_error'] is not None]
        errors = sum(bool(row["semantic_error"]) for row in judgeable_answered)
        present = [row for row in selected if row["outcome"] in {"resolved", "partial", "abstained"}]
        partial_judgeable = [row for row in selected if row.get("partial_assertion_error") is not None]
        partial_errors = sum(bool(row["partial_assertion_error"]) for row in partial_judgeable)
        groups[split] = {
            "eligible_sites": len(selected), "resolved": len(answered),
            "partial": sum(row["outcome"] == "partial" for row in selected),
            "abstained": sum(row["outcome"] == "abstained" for row in selected),
            "missing_or_ambiguous": sum(row["outcome"] in {"missing_claim", "ambiguous_claim"} for row in selected),
            "invalid_contracts": sum(row["outcome"] == "invalid_claim_contract" for row in selected),
            "failed_scans": sum(row['outcome'] == 'scan_failed' for row in selected),
            "resolved_coverage": len(answered) / len(selected) if selected else None,
            "semantic_errors_among_resolved": errors,
            "resolved_semantics_judgeable": len(judgeable_answered),
            "resolved_with_incomplete_reference": len(answered) - len(judgeable_answered),
            "semantic_error_rate_among_resolved": errors / len(judgeable_answered) if judgeable_answered else None,
            "claims_with_structural_errors": sum(bool(row["structural_errors"]) for row in present),
            "boundary_errors": sum(bool(row.get("boundary_error")) for row in present),
            "partial_assertions_judgeable": len(partial_judgeable),
            "partial_assertion_errors": partial_errors,
            "partial_assertion_error_rate": partial_errors / len(partial_judgeable) if partial_judgeable else None,
        }
    return {
        "evaluation_contract": "key-origin-diagnostics-v0.3",
        "analysis_model": MODEL, "status": "review_recorded_diagnostics",
        "review_independence": "declared_by_annotation_record_not_verified_by_software",
        "scope": "No held-out, generalization or novelty claim follows from these diagnostics.",
        "by_split": groups, "cases": rows,
    }
