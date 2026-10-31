# Conditional imports and independent RNG assignment — model v0.2

Work started 30 October 2026 and completed 31 October 2026.

This development checkpoint addresses the two concrete failures recorded in the
[v0.1 audit](METHOD-AUDIT-2026-10-30.md). It changes the bounded analysis model,
not the source populations or human labels. Source code is parsed without being
imported or executed. Reserved origin analysis has not run.

## What changed

Ansible's optional cryptography imports previously lost the `algorithms` API
binding. A bounded exception-prefix join now preserves a unique API alongside
genuinely unbound alternatives, conditional on successful lookup. Bound fallback
conflicts and earlier partial-prefix bindings remain ambiguous. Exception-name
cleanup is modeled; general exception effects still prevent origin resolution.
Visible class methods retain their parameter boundaries and explicit unsupported
method-context reasons. The two AES calls are now abstentions instead of missing.

pyAesCrypt's `encryptStream` invokes a hashing helper before the unrelated
`intKey = urandom(32)`. The earlier global effect barrier also included primitive
guards, named defaults and unrelated class declarations. Model v0.2 separates
unknown helper return values from bounded caller-binding effects. Source-bound
helpers using supported primitive and nominal hash operations can receive a
source-evidenced effect summary. It does not recover their return origins.
Class method bodies are not treated as execution of their enclosing declaration.
Explicit namespace/API mutations, unknown calls and stale function bindings
remain barriers.

The [contract](../../research/python-key-origin/CONTRACT.md) spells out the
additional assumptions: plain builtin inputs for primitive operations, nominal
unmodified APIs and module-initialization entry state. These are **model
assumptions**, not a proof of general Python purity, type safety or correctness.
The summary of `Hash.update` concerns caller bindings; the hash context itself
is mutable. The password-derived key remains unknown. A salt's random origin is
never promoted into proof of a random key.

## Matched development observations

The same seven development projects, 246 selected source files, 19 nominal
candidate sites and candidate translation units were used. Candidate eligibility
and source references still have no completed independent review.

| Condition | v0.1 complete / abstained / missing | v0.2 complete / abstained / missing |
| --- | --- | --- |
| Direct expression | 0 / 17 / 2 | 0 / 17 / 2 |
| Source only | 0 / 17 / 2 | 1 / 18 / 0 |
| AST context | 0 / 17 / 2 | 1 / 18 / 0 |
| CPG context | 0 / 17 / 2 | 1 / 18 / 0 |

The extra abstentions are the formerly missed Ansible calls. The one complete
answer is pyAesCrypt's independent RNG assignment. Its source-only and graph
answers agree, so this result does not demonstrate an added benefit of CPG.
None of these counts is a correctness estimate or detection-recall measurement.
CPG exporter diagnostics about missing node/edge kinds remain in the raw logs;
they are not treated as evidence of complete graph coverage or DFG inference.

The 27 designed development cases retain the same complete/partial/abstained
counts: direct 2/0/25, source-only 15/1/11, AST 19/1/7 and CPG 17/1/9. Provisional
assistant proposals remain development diagnostics, never reviewed truth.

See [v0.2 machine observations](../../research/python-key-origin/expanded-2026-10-30/development-observations-model-v2.json)
and [v0.1 observations](../../research/python-key-origin/expanded-2026-10-30/development-observations-method2.json)
for per-case results, backend/context information, source/code fingerprints and
raw-artifact hashes. Local outputs are `output/model-v2-final-ast`,
`output/model-v2-final-cpg` and `output/model-v2-final-matrix`. They are separate from older
runs. The Docker Python/JEP exporter ran with networking disabled and sources
mounted read-only. No project code or installation scripts were executed.

## Checks and preservation

Host validation passed **215 tests**, including negative fallback/prefix,
exception-alias cleanup, stale/redefined helper bindings, unknown mutations,
eager variadic annotations, effect-versus-return regressions and retention of
effect certificates across conditional expressions. Three real
Python/JEP DFG integration controls passed in Docker; these are the three
environment-specific host skips. Evidence shape checks passed for the new
resolved claim. These checks do not establish semantic soundness or independent
reference correctness.

Current blank packets and proposals explicitly use model v0.2. Historical
[v0.1 inputs](../../research/python-key-origin/model-v1/README.md), downloaded
forms and prior method snapshots are preserved. There were no completed human
reviews to transfer. Old source-review files remain auditable against their
original model/population; current scoring rejects model mixing. New source-only
forms use versioned directories so old downloads or notes are not overwritten.

The active [method snapshot](../../research/python-key-origin/evaluation-freeze.json)
also records the semantic model. It is a post-development snapshot, not a
preregistration. All 33 reserved candidates remain pending independent review;
the origin-evaluation gate still refuses to run them. The 18 unresolved
development origins include parameter, object-field, cross-module and derivation
boundaries. Resolving those needs additional method work and real source review.
The study is not a submission-ready comparative paper.
