# Key-origin contract and review workflow v0.2

The bounded interpreter in `src/cryptograph/key_origin.py` parses source without
importing or executing target code. Its records are separate research outputs;
normal CLI CBOM/risk behavior remains the existing baseline.

## Claim fields

| Field | Meaning |
| --- | --- |
| `analysis_model` | `python-key-origin-subset-v0.2`; older semantic models must not be mixed into a current score. Record format `schema_version` remains `0.1`. |
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

Unknown effects, explicit namespace/API mutation, unsupported control and dynamic
arguments cause conservative unknowns. Cross-module value recovery, general
loops/try/match and decorated wrapper expansion remain unsupported.
These restrictions can substantially reduce coverage. Missing target support
must be reported separately from an explicit abstention.

### v0.2 binding and effect rules

The model changed because additional assumptions support narrower effect
barriers. Historical v0.1 observations are preserved; the change is not a
validated accuracy improvement.

- A limited `try/except` import join retains a unique nominal API when other
  alternatives are genuinely unbound. This is conditional on successful lookup,
  not a claim that import success or the target is reachable. Handler states
  include partial try-body prefixes and exception-name cleanup. Conflicting
  bound fallbacks remain ambiguous. General exception effects still force
  ultimate-origin abstention; `else`/`finally` are not solved.
- Plain class declarations do not execute method bodies at module initialization.
  Bases, metaclass keywords, decorators, eager complex annotations and effectful
  defaults remain barriers. Visible method targets receive an explicit
  `unsupported_method_context` abstention; this is not method value-flow analysis.
- Selected builtin operations (`len`, `bytes`, `str`, `range`, arithmetic and
  comparisons) have binding-effect contracts **assuming plain builtin data**,
  including recursively plain values when conversion/iteration inspects them.
  Custom subclasses, overloaded operators, protocol callbacks, destructors and
  arbitrary object behavior are outside these contracts. Parameters are not
  runtime type-checked by this static experiment.
- Source-visible helpers may receive a bounded no-caller-binding-mutation
  summary without a CALLS witness. The summary checks source reaching bindings,
  primitive local operations and selected nominal RNG/pyca Hash operations.
  `Hash.update` changes its own hash context; that is distinct from changing
  caller API/name bindings. Hash constructors, recognized hash algorithms,
  backend construction and update/finalize behavior are **assumed API
  contracts**, not a Python purity proof. Their documented interfaces are in
  [pyca's hash documentation](https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes/).
  Global/nonlocal writes, unknown calls, object/subscript writes and unsupported
  effects reject the summary. Recursion and expansion have finite limits.
- These certificates retain source spans, import bindings and contract names.
  A helper's unknown return remains unknown. A hash/KDF input derived from a
  random salt does not become a `csprng_api` key. Return-origin expansion still
  requires source binding plus a directed CALLS witness. A later independent
  `os.urandom(32)` assignment can now resolve under the declared model.

Claims assume module-initialization entry state, nominal unmodified libraries
and no earlier unmodeled entry-point mutation/reflection. Ignoring ordinary
`self` field writes while assessing unrelated class declarations does not ignore
recognized API writes or explicit namespace mutation. These restrictions must
be checked against human references before interpreting coverage as usefulness.

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

Use fresh directories. `--check-pilot` checks one claim matching each frozen
source-site span/API/hash and structural validity, not semantic accuracy. Missing
legacy detections remain visible rather than changing the common candidate set.
Existing CBOMs and new claims remain
separate. Four development cells are observable; this is not yet a completed
causal ablation. Legacy source strings lack a comparable set/modality contract,
binding verification must be accounted for, and this version does not evaluate
the added value of DFG recovery.

## Independent review and scoring

No independent review is recorded. All 27 designed cases are development data.

Blank active packets and assistant proposals use v0.2. Their prior versions and
schema are preserved in the repository's `research/python-key-origin/model-v1/`
directory; no human review was
automatically relabeled. Old downloaded forms can be source-audited against
their original packet, but cannot be silently reused for v0.2 scoring. Newly
prepared packets require the current model/contract pair.

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

Work can continue without a reviewer. Explicitly opt in to **provisional
development agreement**, using the separate proposal file:

```bash
python scripts/score-key-origin.py --annotations research/python-key-origin/review-template.json --observations output/policy-ast/observations.json --provisional-proposals research/python-key-origin/review-proposals.json --output output/policy-ast/provisional-agreement.json
```

This mode requires matching proposal IDs, source fingerprints, target spans and
API names. It refuses non-development splits, never fills review slots and
reports proposal disagreement instead of semantic accuracy. A source-inspection
proposal can itself be wrong. Leaving the flag out retains the review gate.

`scripts/run-key-origin-matrix.py` runs direct-expression, source-only, AST CALLS and CPG CALLS cells
and verifies identical candidate and input snapshots. The source-only condition
withholds the graph from the interpreter; its legacy CBOM still uses AST context
and is not a separate legacy baseline. The direct-expression reference verifies
nominal imports and inspects the immediate key expression, without assignment
propagation or helper expansion. Its assumptions are retained in each claim.

The optional `--dfg-probe` records separate bounded DFG dependency paths. Set
`CRYPTOGRAPH_DFG_DEPTH=12` for the backward exporter closure. These paths do not
change key-origin claims, prove feasible execution or resolve ultimate origins.
The exporter records depth, truncation and unresolved-call inference. Raw CPG
columns are retained, while probes require unique source-code/file/line anchors
and an explicit key-argument edge. Ambiguous anchors remain inconclusive.

Reviewed diagnostics separate splits, eligible sites, resolved/partial/abstained
and missing outcomes, invalid contracts, resolved coverage, semantic origin-set
and modality error among resolved claims, boundary errors and structural errors.
Source snapshots must match; duplicate operations and family leakage across
splits are rejected. Structural checks are recomputed using the graph artifact.
Real-project outputs include per-condition observations and a per-project graph
index; witnesses are checked against the corresponding project graph. Use
`--source-root` when downloaded sources live outside the annotation directory.
Failed scans, missing detections and explicit abstentions have separate counters.
Candidate inventories require recorded candidate verification and an independently
declared reviewer role before reviewed scoring. Explicit author/model review is
not accepted as independent review.

Evaluation contract `key-origin-diagnostics-v0.4` judges resolved source-set and
modality assertions only against complete reference sets. Incomplete references
produce a separate resolution-mismatch record and an unjudgeable semantic result,
not an automatic error or a correct answer. Error-rate denominators contain only
judgeable resolved claims; coverage still includes all eligible sites.

For partial claims, asserted categories are checked for membership only when the
reference set is complete. A subset is compatible, not a fully resolved answer.
An incomplete reference cannot establish that an additional category is false;
such comparisons remain unjudgeable. Partial counts, judgeable counts and their
error rate remain separate from resolved coverage/error. Provisional mode uses
proposal-disagreement names for the same mechanics. Finer evidence sufficiency,
path feasibility and completeness validation still require research.

An always-abstain output has zero coverage and a `null` error
rate. Reviewed development diagnostics are not held-out results, statistical
guarantees, proof of generalization or a research contribution by themselves.

## Expanded source review and denominator decisions

The [expanded population](expanded-2026-10-30/README.md) retains development and
reserved inventories independently of the origin interpreter. The nominal
selector collects imports across scopes; it proposes candidates, not verified
API identities. Noncallee references and conflicting supported API identities
are retained separately. Zero primary candidates do not mean zero crypto use.

A completed independent candidate review may explicitly record
`candidate_decision: "ineligible"` with a nonempty `candidate_rationale`. Such a
candidate remains in the frozen inventory and report, but is excluded from the
origin denominator; it needs no invented origin reference. Eligible candidates
require `candidate_verified: true`, `candidate_decision: "eligible"` and a reviewed
reference. Pending/uncertain candidates block reviewed scoring. The counters
`candidate_sites`, `excluded_ineligible_candidates` and `eligible_sites` expose the
denominator change. Historical verified candidates without a decision field
remain compatible. These additions define diagnostics v0.4; v0.3 records remain
historical and are not rewritten.

`scripts/score-key-origin-abstain.py` applies the same review/source gate to a
reference that always abstains. It emits no binding/evidence claims, has zero
resolved coverage and has no defined semantic error rate among resolved answers.
It prevents treating zero output as a useful detector result.

Source-only local review forms are generated by `render-key-origin-review.py`.
Their author mode writes `author_review` and leaves independent records pending.
Independent mode is for a separate human reviewer; identity and actual
independence cannot be verified by the form. No field is pre-approved. Forms
download a new JSON file and do not edit the original packet or send messages.

For expanded development scans, `--graph-scope candidate-files` builds matching
translation units in both backends: each candidate file, or the acquired project
source root for a candidate `__init__.py`. Overlapping units are collapsed.
Fragments retain source paths and exporter metadata; no cross-file edges are
invented. The whole selected source population remains available for review.
Empty graphs at candidate-bearing units are failed scans. This context scope is
different from the historical whole-project-slice runs and is reported explicitly.
The default development phase refuses reserved projects/annotations before
acquisition. The explicit `--phase reviewed-evaluation --freeze <snapshot>` path
first verifies the frozen method, candidate identities, completed independent
review and exact reserved manifest. It refuses pending reviews without creating
an output directory or loading source graphs. This path is implemented for later
use; it has not been run on the reserved origins. Reviewed output still requires
separate scoring with the same source packet and actual graph artifacts.

## Source semantics and failure isolation, second method snapshot

Normal-flow handling now stops at `raise`; a raised branch cannot supply values
to a later normal continuation. An always-raising expanded wrapper leaves an
explicit unresolved boundary. General exception handlers/finally are still
unsupported. Explicit postponed annotations are not treated as eager definition
effects; parameter defaults and decorators remain effect boundaries. These
corrections follow Python's [raise semantics](https://docs.python.org/3.12/reference/simple_stmts.html#the-raise-statement)
and [postponed-annotation feature](https://docs.python.org/3.12/library/__future__.html).
They are regression-covered implementation changes, not independently validated
research gains or a full Python semantics model.

Candidate files/projects, raw hashes, supported APIs, split identities and exact
AST call spans are checked against the acquired manifest before graph analysis.
Nominal binding eligibility still needs human review. Externally located human
annotation files have separate input fingerprints rather than failing because
they are outside the checkout.

CPG failure produces failed graph-context rows while preserving completed direct
and source-only observations. A failed optional DFG probe preserves origin
observations and is reported separately. The overall run still fails; incomplete
runs cannot be captured as completed comparative checkpoints.

JVM export defaults to a 180-second timeout. Configure a finite positive value
up to 3,600 seconds with `CRYPTOGRAPH_EXPORTER_TIMEOUT_SECONDS`. Strict mode
rejects an AST backend masquerading as a successful Fraunhofer export. Research
runs preserve stdout/stderr under each project's `exporter-logs/` directory,
including partial timeout output; ordinary callers can configure
`CRYPTOGRAPH_EXPORTER_LOG_DIR` explicitly. These are analysis integrity controls,
not evidence of graph or origin soundness.

Fresh source-only review bundles refuse existing labels, reviewer notes and
predictions. Restoring a draft validates all identities/API/model/role records
before changing any form fields. Reviewer audit and agreement reports are
available through `scripts/audit-key-origin-reviews.py`; they do not edit source
packets, score the analyzer or approve/adjudicate labels. Shared reviewer IDs are
flagged instead of being presented as independent confirmation.
