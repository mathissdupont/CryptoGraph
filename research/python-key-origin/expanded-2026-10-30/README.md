# Expanded Python source population — 30 October 2026

This extends the historical four-project selected-file study. It is a convenience
sample and a source-review preparation artifact, not a labeled benchmark or a
completed held-out experiment. Original manifests/results remain unchanged.

Eight additional repositories and production source roots were recorded in
[the selection catalog](../repository-selection-2026-10-30.json) before new origin
runs. The non-test source populations were acquired as exact Git blobs at pinned
commits, without checkout filters, importing targets or running build scripts.
Candidate indexing is separate from the origin interpreter. It reads all selected
Python files, including classes and conditional import syntax. It does not prove
binding identity or resolve indirect dispatch.

| New project | Split | Python files | Nominal primary calls |
| --- | --- | ---: | ---: |
| Paramiko | Development | 42 | 1 |
| PyCryptodome | Development / library calibration | 116 | 6 |
| cryptography | Development / library calibration | 78 | 0 |
| OpenStack Barbican | Reserved | 136 | 0 |
| pypdf | Reserved | 59 | 11 |
| pyload | Reserved | 568 | 15 |
| oscrypto | Reserved | 73 | 0 |
| jwcrypto | Reserved | 11 | 6 |

Zero primary calls are retained. They indicate the limits of this selector/API
scope, not the absence of cryptography in a project. Noncallee API references,
conflicting supported imports, parse failures and excluded test/vendor files are
preserved in [screening.json](screening.json). The new projects contribute 1,083
source files and 39 primary candidates. The selector collects imports across
scopes; every candidate still requires human binding/key-role verification.

Combined with the previous records:

- [Development](development-corpus.json): seven projects, 246 selected source
  files and [19 nominal candidates](development-review-template.json).
- [Reserved](evaluation_reserved-corpus.json): seven disjoint projects, 849
  selected source files and [33 nominal candidates](evaluation_reserved-review-template.json).
- Historical projects retain selected-file acquisition, while new projects use
  complete non-test Python roots. This distinction is recorded per project.
- All independent reviews remain pending. Reserved origin analyzers have not
  run. Nominal indexing/acquisition is not an origin prediction or an evaluation.

Trino was screened as a user-suggested large repository and excluded from this
Python study because its implementation is primarily Java. Its pinned revision
and source link remain in the catalog. A separate Java study could investigate
it with a suitable contract and benchmark; no Java/Python scores are pooled here.

## Development observations and context scope

The expanded development run uses identical candidate translation units for AST
and CPG: each candidate file, with the acquired project source root for
`__init__.py`; overlapping units are collapsed. Cross-file graph edges are not
invented. All acquired source files remain available for human review. This scope
is explicit and differs from the earlier project-slice graph condition.

Source-only, direct-expression, AST and CPG origin conditions retain 17 explicit
abstentions and two missing bindings at the 19 development sites. No complete
origin was recovered. The zero-primary-candidate library project remains in the
population rather than being dropped. These outputs expose insufficient current
real-source coverage; adding repositories has not by itself fixed the analyzer.

See the [current development machine record](development-observations-method2.json)
and [previous record](development-observations.json) for per-site
reasons, actual backends, source/code hashes and raw-artifact fingerprints.
Raw graph IDs and environment-specific paths may vary between executions; hashes
identify the retained artifacts rather than promise byte-identical graphs.

The current bounded policy's global effect barriers, unsupported control,
definitions and parameter/object-field boundaries still limit practical coverage.
They must be refined on development data with regression controls. Do not remove
them just to obtain more resolved answers, or tune on reserved origin outputs.
Meaningful development coverage and reliable labels remain prerequisites for the
proposed comparative paper. This artifact does not claim that those are solved.

## Reproduce and review

```bash
python scripts/screen-key-origin-repositories.py --catalog research/python-key-origin/repository-selection-2026-10-30.json --source-root output/expanded-python-sources --out-dir output/new-screening --fetch
python scripts/acquire-key-origin-corpus.py --manifest research/python-key-origin/expanded-2026-10-30/development-corpus.json --root output/development-sources --fetch
python scripts/run-project-key-origin.py --manifest research/python-key-origin/expanded-2026-10-30/development-corpus.json --annotations research/python-key-origin/expanded-2026-10-30/development-review-template.json --source-root output/development-sources --backend ast-lite --graph-scope candidate-files --out-dir output/new-expanded-ast
```

Use fresh output directories. CI replays development acquisition and AST/CPG
conditions, without running reserved origins. GitHub connection tools were used
to pin repository identities/revisions; bulk source acquisition uses Git because
the connector does not provide a bulk binary/source archive export.

Source-review packets with contracts/licenses and browser forms can be prepared
without predictions using `prepare-key-origin-review.py` and
`render-key-origin-review.py`. Author forms write `author_review`; they do not
approve independent references. See the [Turkish first-review guide](../../../docs/research/USER-REVIEW-TR.md).

Diagnostic contract v0.4 retains rejected candidates with reasons outside origin
denominators and provides a gated always-abstain reference. The active method
snapshot is [evaluation-freeze.json](../evaluation-freeze.json). The older
snapshot is preserved as [evaluation-freeze-v1.json](../evaluation-freeze-v1.json).
The first expanded-population snapshot is preserved as
[evaluation-freeze-v2.json](../evaluation-freeze-v2.json). The
[method integrity audit](../../../docs/research/METHOD-AUDIT-2026-10-30.md)
describes later source semantics, failure isolation and human-review checks.
This is a method snapshot after development, not a preregistration or completed
human review. The reserved population has not been used to tune origin behavior.
