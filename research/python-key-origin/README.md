# Python key-origin feasibility pilot

These 24 small programs probe what CryptoGraph says about the origin of an
AES key across PyCryptodome and pyca/cryptography. They were authored during
research scoping and development on 27 October 2026. They are
**not independently annotated ground truth, a held-out benchmark, or evidence of
general accuracy**. The manifest records review questions instead of scored labels.

The programs are intentionally insecure examples. Parse them as data; do not use
them as encryption implementations. The harness never imports or executes them.
The original eight fixtures use ECB to hold the API shape constant. Added
fixtures include AES/AESGCM constructors, configuration defaults, partial source
sets, argument binding, loops and opaque external factories. Misuse detection
is not the measurement in this pilot.

## Reproduce

From an installed source checkout:

```bash
python scripts/research-pilot.py --backend ast-lite --out-dir output/key-pilot-ast
```

For the real Python frontend, build the existing runtime image, then run the same
script through Docker Compose, which mounts the checkout under `/app`:

```bash
docker compose build cryptograph
docker compose run --rm --entrypoint python cryptograph scripts/research-pilot.py --backend fraunhofer-strict --out-dir /results/key-pilot-cpg
```

Use new output directories on subsequent runs. Each run writes a CBOM, full graph,
observations and a record containing actual backend, environment and input hashes.
Strict mode does not substitute AST-lite if the exporter fails. The main study
will require a pinned environment and an independently reviewed corpus.

## Preserved observations from the original eight cases

Both AST-lite and the full Docker Python/JEP/Fraunhofer path produced the following
key-source strings for the eight `AES.new` targets:

| Case | Observed key source | Interpretation requiring review |
| --- | --- | --- |
| `direct_random` | `generated_random` | Positive control with an `os.urandom` assignment. |
| `misleading_helper` | `generated_random` | The helper returns repeated constant bytes; its name alone is not randomness evidence. |
| `assignment_after_sink` | `generated_random` | The call consumes a literal-backed key; the random assignment occurs afterwards. |
| `mixed_branch` | `hardcoded_constant` | One branch uses randomness and the other a literal. The field does not express whether it denotes a possible or definite source. |
| `parameter_boundary` | `function_parameter` | A correct immediate boundary does not resolve an ultimate upstream origin. |
| `aliased_random` | `return_value` | A coarse call boundary; not equivalent to a false randomness claim. |
| `literal_final_assignment` | `hardcoded_constant` | Positive control for an overwritten random assignment before the call. |
| `wrapper_random` | `return_value` | A coarse wrapper boundary; more context might resolve it. |

The full Docker runtime built and ran the Python frontend successfully. The
normalized CPG had 103 nodes and 135 edges for this pilot. Its exporter still
reported incomplete normalized node/edge kinds; these counts do not establish
graph completeness or interprocedural correctness.

Two mechanisms in the current code explain concrete concerns: substring-based
randomness classification in `flow_analyzer.py`, and a function-wide assignment
dictionary in `context_extractor.py` that is not indexed by the sink location.
Repairing those mechanisms alone would be an implementation fix, not a new
research contribution. This pilot preserves the observations before changes.

## Preserved bounded-policy comparison on the original eight cases

The new policy is available separately from the existing CBOM heuristic:

```bash
python scripts/research-pilot.py --backend ast-lite --policy both --check-pilot --out-dir output/policy-ast
```

See [CONTRACT.md](CONTRACT.md) for the Docker/CPG command, schema, limitations and
review instructions. The matched-input development runs produce:

| Case | AST evidence-policy output | CPG evidence-policy output |
| --- | --- | --- |
| `direct_random` | `csprng_api`, must | same |
| `misleading_helper` | `literal`, must | abstained: matching wrapper witness unavailable |
| `assignment_after_sink` | `literal`, must | same |
| `mixed_branch` | `csprng_api` + `literal`, may | same |
| `parameter_boundary` | abstained; parameter boundary retained | same |
| `aliased_random` | `csprng_api`, must | same |
| `literal_final_assignment` | `literal`, must | same |
| `wrapper_random` | `csprng_api`, must | same |

In the CPG export, the `misleading_helper` CALLS target is a DFG-classified,
inferred node with no matching function span and a different source file. The
policy rejects that witness. This is an observation about the exported graph,
not a root-cause finding about the CPG library. AST resolves seven ultimate source
sets and abstains on one; CPG resolves six and abstains on two in this run.

These are model-conditional outputs on examples used during implementation, not
an independently validated accuracy result. The current policy consumes source
syntax and CALLS witnesses; these outputs do not establish a general absence of
CPG benefit. Independent review is pending. Reviewed metrics require a completed
review record; explicitly provisional development agreement is available separately.
Source fixtures use fixed LF line endings to keep their
review fingerprints stable across operating systems.

## Matched 24-case development experiment

Run all three bounded-policy conditions in the full Python/JEP Docker runtime:

```bash
docker compose build cryptograph
docker compose run --rm --entrypoint python cryptograph scripts/run-key-origin-matrix.py --out-dir /results/key-origin-matrix --provisional-proposals research/python-key-origin/review-proposals.json
```

Use a fresh output directory. Omit `--provisional-proposals` to retain raw
observations without comparing unreviewed labels. The runner checks identical
source/config/code hashes, declared candidate spans and proposal fingerprints
across cells. All cells use the same bounded source interpreter. The source-only
cell withholds graph witnesses; AST and CPG cells can authorize same-file calls.
The legacy CBOM heuristic is recorded alongside these cells, with its different
output contract preserved.

| Bounded-policy context | Complete source sets | Partial sets | Abstentions | Claims using CALLS |
| --- | ---: | ---: | ---: | ---: |
| Source only | 13 | 1 | 10 | 0 |
| AST-derived CALLS | 17 | 1 | 6 | 4 |
| Fraunhofer CALLS | 15 | 1 | 8 | 2 |

All 24 declared sites produced one structurally checked claim in each condition.
The legacy matcher found 23 sites and missed the aliased AESGCM constructor.
This difference is retained as detection coverage, not an abstention. The CPG
condition rejected wrapper witnesses in `misleading_helper` and
`wrapper_actual_parameter` that the AST condition could accept.

Resolved sets did not disagree with the unreviewed assistant proposals in this
run. This is **development agreement, not measured accuracy**. One boundary
disagreement remains: `unsupported_loop` has proposed `local_assignment` while
the interpreter emits `expression` after unsupported writes. It is recorded
without changing the proposal to fit the output. Partial-set semantic error
measurement remains to be designed; partial claims are not counted as complete.

The optional [PQCensus observation adapter](../../scripts/observe-pqcensus.py)
pins a source revision, retains native outputs and checks positive controls. Its
inspected revision did not detect these AES constructors and has no equivalent
ultimate key-origin contract. This is not a suitable origin-accuracy comparator;
see [the expanded checkpoint](../../docs/research/EXPANDED-2026-10-27.md).

## Study boundary

Do not compute a publication accuracy number from these cases. Before evaluation,
define the meaning of an origin claim, annotate source sets and uncertainty,
obtain independent review, freeze development/test splits and compare appropriate
baselines. See [the protocol](../../docs/RESEARCH.md) and
[literature screening](../../docs/research/LITERATURE-2026-10-27.md).
