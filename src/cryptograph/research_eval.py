"""Review-gated diagnostics for the development key-origin experiment."""
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


def score_reviewed(annotations: dict, observations: dict, source_root: Path, graph: NormalizedGraph | None = None) -> dict:
    """Compute diagnostics only after a declared independent review is recorded.

    The gate checks the review record's shape, not the reviewer's identity or
    actual independence. Development-case metrics remain development diagnostics
    even after review; they do not become held-out research results.
    """
    if annotations.get("analysis_model") != MODEL or observations.get("analysis_model") != MODEL:
        raise ValueError("Analysis model mismatch")
    if observations.get("policy") not in {"both", "evidence"}:
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
        or not entry.get("independent_review", {}).get("reviewed_reference")]
    if pending:
        raise ReviewPending("Independent review is pending for: " + ", ".join(pending))
    observed = {case["case_id"]: case for case in observations["cases"]}
    rows = []
    for entry in entries:
        path = (source_root / entry["source"]).resolve()
        if not path.is_relative_to(source_root.resolve()):
            raise ValueError("Annotation source is outside the corpus")
        if hashlib.sha256(path.read_bytes()).hexdigest() != entry["source_sha256"]:
            raise ValueError(f"Reference source changed: {entry['case_id']}")
        reference = OriginReference.model_validate(entry["independent_review"]["reviewed_reference"])
        candidates = []
        for item in observed[entry["case_id"]].get("evidence_policy", []):
            payload = item.get("claim", {})
            if payload.get("target") == entry["target"] and payload.get("target_api") == entry["target_api"]:
                candidates.append(payload)
        row = {"case_id": entry["case_id"], "split": entry["split"], "scenario_family": entry["scenario_family"]}
        if len(candidates) != 1:
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
            structural_errors = audit_claim_structure(claim, path, graph)
            semantic_error = None
            if claim.status == "resolved":
                semantic_error = (
                    sorted(claim.origins) != sorted(reference.origins)
                    or claim.modality != reference.modality
                    or not reference.origin_set_complete
                )
            row.update(outcome=claim.status, semantic_error=semantic_error,
                       boundary_error=claim.immediate_boundary != reference.immediate_boundary,
                       structural_errors=structural_errors)
        rows.append(row)

    # Keep different splits separate; development data must not be pooled into
    # an apparent held-out score. No uncertainty interval is implied here.
    groups = {}
    for split in sorted({row["split"] for row in rows}):
        selected = [row for row in rows if row["split"] == split]
        answered = [row for row in selected if row["outcome"] == "resolved"]
        errors = sum(bool(row["semantic_error"]) for row in answered)
        present = [row for row in selected if row["outcome"] in {"resolved", "partial", "abstained"}]
        groups[split] = {
            "eligible_sites": len(selected), "resolved": len(answered),
            "partial": sum(row["outcome"] == "partial" for row in selected),
            "abstained": sum(row["outcome"] == "abstained" for row in selected),
            "missing_or_ambiguous": sum(row["outcome"] in {"missing_claim", "ambiguous_claim"} for row in selected),
            "invalid_contracts": sum(row["outcome"] == "invalid_claim_contract" for row in selected),
            "resolved_coverage": len(answered) / len(selected) if selected else None,
            "semantic_errors_among_resolved": errors,
            "semantic_error_rate_among_resolved": errors / len(answered) if answered else None,
            "claims_with_structural_errors": sum(bool(row["structural_errors"]) for row in present),
            "boundary_errors": sum(bool(row.get("boundary_error")) for row in present),
        }
    return {
        "analysis_model": MODEL, "status": "review_recorded_diagnostics",
        "review_independence": "declared_by_annotation_record_not_verified_by_software",
        "scope": "No held-out, generalization or novelty claim follows from these diagnostics.",
        "by_split": groups, "cases": rows,
    }
