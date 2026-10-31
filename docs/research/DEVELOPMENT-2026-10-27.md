# Key-origin development checkpoint - 27 October 2026

## Implemented

- Separate bounded key-source inference with source/API binding, ordering,
  source sets, modality and explicit unknowns.
- Source-located evidence, retained CALLS witnesses and structural auditing.
- Both-policy recording under AST-derived and real Fraunhofer Python graphs.
- Fingerprinted review templates, separate assistant proposals and review-gated scoring.
- Checks for duplicate operations, family leakage, source mismatches, stale
  outputs and missing claims being confused with abstentions.

## Development observations

Both backends used the same Docker Python/JEP runtime and matching
source/config/analysis-code hashes. All eight legacy targets were found in each
run. The new claims had no reported structural audit errors.

| Context | Existing policy | Bounded policy |
| --- | --- | --- |
| AST-derived | Misleading helper and post-target assignment labeled `generated_random`; branch sources collapsed. | Seven complete sets and one abstention. The two concerning examples emitted `literal`; the branch retained both may origins. |
| Fraunhofer CPG | Same legacy strings on those cases. | Six complete sets and two abstentions. Post-target assignment emitted `literal`; misleading helper abstained for lack of a matching wrapper witness. |

The exported helper CALLS target was an inferred, DFG-classified node without a
matching function location and with a different file identifier. The policy
rejected it. This is an exported-graph observation, not a root-cause attribution
to the upstream library.

All cases were used during implementation. Counts are engineering observations,
not independently validated accuracy or superiority. The policy currently uses
source syntax and CALLS, not DFG value recovery; fuller context ablations remain.

## Checks

- 85 tests passed locally, including real Java exporter and optional UI checks.
  49 exercise the new policy, auditor, scoring mechanics and corpus fingerprints.
  Unit review records are explicitly synthetic fixtures.
- Full Python/JEP Docker runtime built; current source was mounted read only
  for matched-input runs with network disabled.
- Pending-review scoring returned exit 2 and wrote no score.
- Wheel/source distribution built with the modules, schema and review packet.
- CI now defines a full Docker Python research job retaining observations.
  Remote results depend on the new commit's run.

## Remaining work

No independent reviewer or approved annotation record is available. Assistant
proposals must not fill approval slots. A reviewer should inspect source and
[the contract](../../research/python-key-origin/CONTRACT.md) before outputs/proposals.

Independent review, a larger grouped corpus, held-out projects, fair external
comparators, partial-set semantic scoring, fuller DFG experiments and statistical
evaluation remain outstanding. No paper accuracy or novelty claim is made.
