# Key-origin contract and review workflow v0.1

The bounded interpreter in `src/cryptograph/key_origin.py` parses source without
importing or executing target code. Its records are separate research outputs;
normal CLI CBOM/risk behavior remains the existing baseline.

## Claim fields

| Field | Meaning |
| --- | --- |
| `operation_id`, `target` | A source call/key role with line and UTF-8 byte-column span. Two calls on one line remain distinct. This pilot uses unique file basenames. |
| `source_sha256` | Hash of raw source bytes, including line endings. |
| `immediate_boundary` | Literal, assignment, parameter, return value or expression, distinct from ultimate origin. |
| `origins` | Supported ultimate categories: `literal`, `csprng_api`, `external_configuration`. |
| `origin_set_complete` | The interpreter's completeness assertion within its subset/model, to be evaluated rather than assumed correct for arbitrary Python. |
| `status` | `resolved` for a nonempty complete set, `partial` for known categories plus unresolved alternatives, `abstained` for no ultimate category. |
| `modality` | `must` for one resolved category, `may` for multiple/partial alternatives, `unknown` for abstention. |
| `unresolved_reasons` | Parameter boundaries, missing bindings, unsupported effects or expansion limits. |
| `context_backend`, `graph_features_used` | The supplied graph and the features actually used. |
| `evidence` | Source spans, derivation parents and raw CALLS-edge witnesses. |

See [claim.schema.json](claim.schema.json). `literal` includes supported constant
composition. `csprng_api` identifies a recognized API origin, not key security,
freshness, entropy quality, length, lifetime or deployment correctness.

## Model and limits

Supported targets are PyCryptodome/Cryptodome `AES.new`, pyca `algorithms.AES` and
`AESGCM`. Sources include nominal bindings to `os.urandom`, `secrets.token_bytes`,
literals and environment reads, including defaults. Imports/aliases, ordered
assignments, overwrites, `if`, conditional expressions and early returns are
handled. Same-file module wrappers can expand when source resolution,
actual/formal binding and a directed CALLS witness agree.

Both AST and CPG graphs can provide that witness. This version uses CALLS,
**not DFG value recovery**. Root functions have unknown parameters after module
initialization. Intended library identity/API contracts and valid target inputs
are assumptions. External monkey patching, import hooks, concurrent mutation and
feasible-path proofs are outside the model. May sets are abstract alternatives;
path correlations are not solved.

Unknown effects, explicit attribute writes, unsupported control and dynamic
arguments cause conservative unknowns. Classes/methods, cross-module wrappers,
general loops/try/match and decorated/defaulted wrapper expansion are unsupported.
These restrictions can substantially reduce coverage. Missing target support
must be reported separately from an explicit abstention.

The auditor checks raw source identity, AST spans, evidence closure/cycles,
disconnected steps, local assignments after a target and graph witnesses against
the supplied graph. It does not independently establish correct source semantics
or feasible execution. Valid evidence shape and a correct conclusion are distinct.

## Run the development comparison

```bash
python scripts/research-pilot.py --backend ast-lite --policy both --check-pilot --out-dir output/policy-ast
docker compose build cryptograph
docker compose run --rm --entrypoint python cryptograph scripts/research-pilot.py --backend fraunhofer-strict --policy both --check-pilot --out-dir /results/policy-cpg
```

Use fresh directories. `--check-pilot` checks one target per committed case and
structural validity, not semantic accuracy. Existing CBOMs and new claims remain
separate. Four development cells are observable; this is not yet a completed
causal ablation. Legacy source strings lack a comparable set/modality contract,
binding verification must be accounted for, and this version does not evaluate
the added value of DFG recovery.

## Independent review and scoring

No independent review is recorded. All eight cases were used during development.

- `review-template.json` holds source hashes, spans, families and empty review slots.
- `review-proposals.json` holds separate assistant-generated source-inspection
  proposals. They are not ground truth and are never auto-loaded by the scorer.
- For blind review, provide sources, the template and contract first; withhold
  proposals/outputs until independent annotations and reasons are recorded.
- Record a reviewer identifier, `approved` status and `reviewed_reference` only
  after actual review. Software cannot verify identity, expertise or independence.
  Preserve disagreements and adjudication separately.

```bash
python scripts/score-key-origin.py --annotations research/python-key-origin/review-template.json --observations output/policy-ast/observations.json --output output/policy-ast/reviewed-score.json
```

The pending template intentionally returns exit **2** and writes no score.
Invalid/mismatched inputs return **3**; existing output paths are rejected to
avoid stale scores. Proposals remain separate after review.

Reviewed diagnostics separate splits, eligible sites, resolved/partial/abstained
and missing outcomes, invalid contracts, resolved coverage, semantic origin-set
and modality error among resolved claims, boundary errors and structural errors.
Source snapshots must match; duplicate operations and family leakage across
splits are rejected. Structural checks are recomputed using the graph artifact.

Partial-set semantic scoring and finer-grained evidence sufficiency still need
evaluation design. An always-abstain output has zero coverage and a `null` error
rate. Reviewed development diagnostics are not held-out results, statistical
guarantees, proof of generalization or a research contribution by themselves.
