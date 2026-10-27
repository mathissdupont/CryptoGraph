# Research protocol: Python key-origin evidence

## Decision and scope

The first study targets **Python** and **key-material origin claims** at
cryptographic call sites. Candidate library scope is PyCryptodome and
`cryptography`; the current feasibility probes use PyCryptodome AES construction.
The initial runtime is Python 3.12 in Docker. AST-lite and the bundled Fraunhofer
Python frontend are analysis conditions, not assumed equivalent implementations.

This choice follows the [literature and language screening](research/LITERATURE-2026-10-27.md)
and a [small local feasibility pilot](../research/python-key-origin/README.md).
It does not establish which language uses the most cryptography. Other language
configurations remain experimental project capabilities, outside this study.

Application intent, PQC migration advice, general misuse detection accuracy and
LLM reasoning are outside the first study. IV/nonce provenance may be a later
extension after the key-origin contract and evaluation are stable.

## Research question

**Can explicit evidence requirements reduce unsupported key-origin claims in
Python cryptographic inventories while retaining useful coverage, and what
additional benefit does CPG context provide over AST context?**

This is a candidate empirical contribution, not a claim of firstness or a proven
new analysis method. Contextual crypto analysis, provenance annotations, metadata
origin and abstention all have prior work. Repairing ordinary reaching-definition
or name-resolution bugs in CryptoGraph alone would be an engineering contribution.

Research questions:

1. **Claim fidelity:** Under which Python constructs do reported key origins
   diverge from the origins justified by the source and declared analysis model?
2. **Evidence policy:** How does requiring admissible evidence change semantic
   error, invalid-evidence rate, abstention and coverage?
3. **Context contribution:** With matching and evidence policy held constant,
   what additional source claims can CPG context recover correctly over AST?

## Define a claim before scoring it

The evaluation unit is an annotated cryptographic operation/call site and key
role, identified by revision, source span and operation. Constructor/helper
duplication must not increase the denominator. Each proposed claim record needs:

- immediate boundary: literal, expression, parameter, object field or return value;
- ultimate origin category/set when resolvable, e.g. literal-derived material,
  a recognized CSPRNG API, KDF output or external configuration;
- modality: possible origin (`may`), definite origin under the declared model
  (`must`), mixed origins or unresolved;
- evidence: source spans, symbol binding, assignment ordering and any directed
  dependency/actual-formal binding path used in the derivation;
- unresolved reasons and relevant assumptions.

The bounded v0.1 research implementation now supplies this contract separately;
see [the contract, limits and review workflow](../research/python-key-origin/CONTRACT.md).
It initially supports literal, recognized CSPRNG API and environment categories;
KDF provenance and general Python semantics are not implemented. The legacy
`flow.key_source` string conflates some boundaries and origins and lacks explicit
may/must semantics. An `os.environ` source may be identifiable while the runtime
key value is unknown. A parameter boundary may be correct while its ultimate
source is unresolved. A mixed branch must not be silently treated as one definite
runtime source. Generic `return_value` is a coarse answer, not automatically an
incorrect claim.

An observed graph edge does not prove feasible execution. Graph reachability is
not by itself path sensitivity or a runtime guarantee. A recognized CSPRNG call
does not prove deployment security, key uniqueness, lifetime or entropy quality.
Use source/API-origin terminology, not a global "secure key" assertion.

## Analysis model and proposed evidence requirements

Define supported Python syntax, API contracts and closed-world assumptions before
annotation. Dynamic rebinding, monkey patching, reflection, native implementations
and unresolved imports require explicit boundaries. Do not quietly assume that
all Python programs satisfy a closed-world model.

Candidate requirements include a resolved and unshadowed API binding, an
assignment that can reach the key argument before its use, explicit handling of
overwrites and branches, and justified bindings across wrappers. A function name
containing `urandom` is insufficient. A later assignment cannot supply a value to
an earlier call. Missing definitions can justify an immediate boundary while
requiring abstention on a more specific upstream category.

The first bounded subset is implemented and behaviorally tested. It is not a
formal soundness proof. Correct source-origin claims and structurally valid evidence are separate
properties and must be evaluated separately.

## Experimental conditions

Hold source snapshots, API mappings, normalization, source categories and output
matching constant. Plan a factorial comparison:

| Context | Existing inference policy | Proposed evidence-constrained policy |
| --- | --- | --- |
| AST-derived graph | A | B |
| Fraunhofer CPG | C | D |

The pilot runner now records both policies under either backend. The bounded
policy uses the same source interpreter in both contexts and currently consumes
CALLS witnesses, not DFG value recovery. AST-derived graphs can also authorize
same-file wrapper expansion. Four development cells are observable, but a complete
causal ablation remains pending: legacy strings lack the new modality/set
contract, and target-binding differences need to be accounted for. Add a
literal/direct-call reference and a common candidate population before claiming
a controlled held-out comparison. The old and v2 matchers are not valid A/B
experimental conditions by themselves.

External comparators are screened on overlapping tasks and APIs: CBOMkit for
inventory/parameters, and appropriate Python misuse tools for their documented
claims. CRYPTBARA is relevant related work, with actual model experiments
deferred. PQCensus is a candidate engineering comparator. Preserve each tool's
claim granularity. A tool that never emits key-origin fields must not be scored
as inventing origins. Run failures remain visible and are not successful abstentions.

## Corpus and annotation

The eight committed probes are development cases, authored to inspect failure
mechanisms. Their observations are not independent ground truth or an accuracy
estimate. Preserve them before implementing repairs.

Design the annotation pilot around direct calls, aliases, shadowing, wrappers,
reassignment, assignments after the call, branches, parameters, configuration
sources and unrelated flows. Include pairs where syntactic changes preserve the
origin and pairs where one dependency change must alter the answer. Validate
transformation preconditions; a renamed external API is not automatically
semantics preserving.

Begin with a manageable manually reviewed labeling pilot, then set corpus size
and sampling policy using label cost and error diversity. Add pinned real-project
excerpts on shared APIs. Record provenance and reuse terms. Obtain independent
annotation/review, retain disagreements and adjudication, and allow unknowns.
Never generate reference labels from analyzer output or model assertions alone.

Split by project and base scenario family before tuning gates. Transformed copies
of a template must not straddle development and held-out evaluation. Existing
misuse datasets require additional origin/evidence labels; they do not supply
them automatically. Acquisition of a complete PyCryptoBench release remains
unresolved; see the screening notes.

## Measurements

Report these separately:

- detection precision/recall for annotated eligible call sites;
- semantic origin error among answered claims, with explicit handling of sets
  and may/must statements;
- structurally invalid or unsupported evidence among emitted claims, even if a
  conclusion happens to be correct;
- claim coverage: answered eligible sites / all eligible annotated sites;
- coarse-boundary, mixed and unresolved rates, with reasons;
- parser failures, missed targets, fallback/backend identity and runtime.

Show error versus coverage for predefined policies, and compare at matched
coverage where feasible. Report an always-abstain reference; zero claims cannot
establish a useful detector. Separate ambiguity inherent in the input/model from
information the implementation failed to recover. No heuristic confidence value
is a calibrated probability without an independent calibration evaluation.

Use paired comparisons on common inputs, keep scenario families grouped, report
uncertainty appropriate to the sample and avoid treating generated variants as
independent evidence. Freeze all versions and settings before a held-out run.

## Decision gates and publication boundary

Proceed beyond the pilot if the label contract is reproducible, the task differs
meaningfully from existing misuse/inventory benchmarks, comparison artifacts can
be obtained, and the evaluation can distinguish useful evidence from cheap
abstention. A positive superiority result is not mandatory; well-supported
negative findings or failure mechanisms may still be informative.

Reframe or narrow the study if labels remain ambiguous, artifacts cannot support
a fair comparison, findings reduce to simple bugs unique to CryptoGraph, or
evidence gates only suppress nearly all output. Do not turn this scoping review
into a novelty or publishability claim.

The full Docker runtime and real Python frontend now run on the eight probes.
That establishes feasibility, not complete graph semantics or general accuracy.
The earlier [validation snapshot](VALIDATION.md) records implementation checks;
the pilot records the later Python feasibility observation. CycloneDX conformance
and actual LLM integration remain separate unfinished work.
