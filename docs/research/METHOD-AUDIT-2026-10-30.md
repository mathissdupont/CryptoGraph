# Method integrity audit — 30 October 2026

This extends the [expanded source study](../../research/python-key-origin/expanded-2026-10-30/README.md).
The prior population, observations and method snapshots are preserved. No
reserved origin analyzer or independently reviewed accuracy measurement ran.

## Implemented and checked

- Raising branches stop normal continuation; unreachable calls after a raise do
  not create function-entry claims. Always-raising expanded wrappers remain
  unresolved. General try/except/finally handling is still outside the subset.
- Explicit postponed annotations no longer create eager annotation-effect
  barriers. Defaults/decorators and unknown call effects remain conservative.
- Candidate/project identity, manifest membership, raw source hashes, API scope,
  split, duplicate operation identities and exact call spans are checked before
  graph construction. These checks do not certify nominal API bindings.
- Graph construction failure is isolated from the independent direct/source-only
  methods. Optional path-probe failure does not destroy valid origin outputs.
  Overall run failures remain visible and cannot become completed checkpoints.
- JVM exports have a configurable 180-second default deadline. Strict mode
  rejects AST provenance. Research output retains exporter diagnostics, including
  partial timeout stdout/stderr.
- Source-only forms reject prefilled labels/predictions. Draft restoration checks
  the entire file's identities before changing current fields, including API and
  reviewer role, and accepts reordered JSON object keys.
- Human review auditing validates role/source/label contracts and compares
  completed pairs, keeping pending cases and disagreements explicit. Agreement
  does not establish truth; shared reviewer IDs are flagged. No record is
  automatically adjudicated or approved.

The host suite passed **195 tests**; three Python/JEP-specific checks are run in
the Docker CI job. Fault controls use synthetic fixtures and are not real human
review records. The installed research wheel/source distribution and final CI
results are checked separately from semantic research validity.

The matched designed matrix remains 2/0/25, 15/1/11, 19/1/7 and 17/1/9
(complete/partial/abstained). Expanded development outputs remain 17 abstentions
and two missed bindings at 19 nominal sites. The corrections do not establish
improved real-project coverage. See the
[current machine record](../../research/python-key-origin/expanded-2026-10-30/development-observations-method2.json)
and [previous record](../../research/python-key-origin/expanded-2026-10-30/development-observations.json).

## Publication readiness

| Requirement | Current state |
| --- | --- |
| Pinned source populations and reproducible development execution | Implemented, with explicit source/selector/context limits. |
| Source-only review collection and consistency checking | Implemented; no actual human reviews submitted. |
| Independent candidate/origin references | Pending. |
| Useful real-source ultimate-origin coverage | Not established; current complete coverage is zero. |
| Comparable external ultimate-origin endpoint | Not reproduced; CBOMkit remains a native inventory observation. |
| Held-out semantic evaluation | Not executed. |
| Generalization, novelty or detector superiority | Not established. |
| Submission-ready comparative paper | Not ready. |

The next human task is the [four-case author review](USER-REVIEW-TR.md). Those
training notes are not independent ground truth. Method development on real
development code and a separate source-based review are still needed before
held-out evaluation. Passing regressions or adding repositories does not fill
these scientific gaps. They are deliberately not marked completed by this audit.

Review files can be audited without running an origin analyzer:

```bash
python scripts/audit-key-origin-reviews.py --annotations output/research-author-start/annotations.json --source-root output/research-author-start/sources --review output/project_author-review.json --output output/review-audit.json
```

With two independent input files, repeat `--review`; comparisons retain blank
human adjudication records. The inputs are not changed. Source review still needs
actual people and expertise; software checks only the recorded declarations and
structural consistency.
