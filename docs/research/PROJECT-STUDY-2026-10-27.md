# Python key-origin: project feasibility and value-dependency experiments

Final development reproduction: **30 October 2026**.

This checkpoint extends the [24-case development run](EXPANDED-2026-10-27.md).
It is a reproducible feasibility study, with unreviewed candidate/reference
records. It does not establish origin accuracy, generalization or a novel method.

## Designed development conditions

The corpus has 27 programs. New controls cover an unrelated RNG value, a random
salt passed to a password KDF, and an AES constructor nested inside `Cipher`.
All programs are parsed as data. They are not encryption examples to deploy.

| Condition | Candidate sites | Complete source sets | Partial | Abstained |
| --- | ---: | ---: | ---: | ---: |
| Direct expression, nominal imports | 27 | 2 | 0 | 25 |
| Source interpreter, no graph witnesses | 27 | 15 | 1 | 11 |
| Same interpreter with AST CALLS | 27 | 19 | 1 | 7 |
| Same interpreter with Fraunhofer CALLS | 27 | 17 | 1 | 9 |

The direct reference inspects only the immediate expression; it does not
propagate assignments or expand helpers. The other three conditions share one
source interpreter. A fixed candidate inventory and source/config/code hashes
are checked across conditions. Legacy CBOM strings are preserved separately;
their lack of set/modality semantics is not repaired by an arbitrary adapter.
Provisional proposal agreement is a development check, not measured accuracy.

The previous loop-boundary mismatch was fixed without changing its proposal:
unsupported writes retain `local_assignment`, while the ultimate origin still
abstains. The original development observations remain archived.

## Real-project acquisition

Four projects were selected as a convenience sample of crypto-related modules.
Twelve nominal AES call sites in seven complete implementation files were
inventoried before origin runs. Their binding/key-role eligibility still needs
human verification. Three original package `__init__.py` files were subsequently
added for scanner compatibility; all tools receive the same expanded tree.
The acquisition retains 10 source files and five license documents.

| Project | Pinned revision | Implementation candidates | License records |
| --- | --- | ---: | --- |
| [matrix-nio](https://github.com/matrix-nio/matrix-nio/tree/331c93ed3e9ca86e7444b4dfdf05086654842ace) | `331c93e` | 4 | Repository ISC and Apache documents; selected implementation files have Apache headers. |
| [pyAesCrypt](https://github.com/marcobellaccini/pyAesCrypt/tree/13a188f8799306ad9034167bf0bc0489319db274) | `13a188f` | 4 | Apache-2.0. |
| [SecretStorage](https://github.com/mitya57/secretstorage/tree/ac7bd14bb8a95cb1eb9185dfee056ec850ff50ca) | `ac7bd14` | 2 | BSD-3-Clause. |
| [Ansible](https://github.com/ansible/ansible/tree/5186cff137018276877e2e6c24e669ec46098d2a) | `5186cff` | 2 | GPL-3.0-or-later file headers and GPL text. |

[project-corpus.json](../../research/python-key-origin/project-corpus.json)
contains full commits, original paths, URLs, exact byte counts and SHA-256
fingerprints. Downloaded source/license files remain outside Git. The downloader
validates every URL/path before fetching, rejects changed cache entries and
parses source without importing it. It does not acquire full dependency closures
or complete project checkouts. This limits interprocedural interpretation.

The source-only, AST and CPG origin conditions emitted ten explicit abstentions
and missed two candidate bindings. No ultimate origin was fully resolved in
this sample. The direct-expression reference also had ten abstentions and two
missing bindings. Ansible imports `algorithms` inside a `try`; this source-binding
form is outside the interpreter's supported import subset. Missing candidates
are not counted as abstentions. Every emitted claim retains its unresolved
reasons and structural audit results. These observations expose a coverage
problem; the designed examples do not establish real-project usefulness.

## Separate DFG experiment

The exporter can opt in to predecessor expansion from call arguments with
`CRYPTOGRAPH_DFG_DEPTH=12`. It records depth, limits, truncation and the enabled
inference of DFG for unresolved calls. The path observer requires unique
file/code/line anchors, a target argument edge and directed DFG edges. It rejects
ambiguous anchors and distinguishes a missing path, a search limit and an
inconclusive truncated export. Raw CPG regions are preserved without assuming
their columns are Python UTF-8 byte columns.

The `kdf_random_salt` control exported a ten-edge RNG-to-key dependency path.
The origin policy still abstains. PBKDF2 derives key material from a password
and salt, so this dependency does not establish that the key is the direct
CSPRNG result. This interpretation follows the
[PBKDF2 API contract](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#pbkdf2).
The unrelated-RNG control exported a literal-to-key path and no RNG-to-key path.
These are regression/control observations, not an independently annotated DFG
accuracy result or a complete provenance analysis.

Nested AES calls were initially retained as generic argument nodes when the
outer call was visited first. The exporter now keeps the authoritative call
record when that expression is visited. JVM and Python/JEP regressions cover
this correction. It prevents a representation loss; it is not a new research
contribution by itself.

DFG observations are separate artifacts. They never promote an unknown or
partial ultimate-origin claim into a resolved one. Feasible paths, transformations,
cross-module semantics and complete origin-set recovery remain unvalidated.

## Native CBOMkit reproduction

The [official action](https://github.com/cbomkit/cbomkit-action/tree/847c980e33b166603b39578472c9a04bbea238e2)
was run from immutable image digest
`sha256:7dfc905c614549fdb630d41a33b34a039af7f60c982501c6d74dfc63ef700512`.
Its image label declares the inspected source revision. Scans select Python,
disable module CBOM splitting, use an explicit never-matching exclusion regex,
run with networking disabled and mount source read only. Each project is scanned
separately. Logs and native CycloneDX 1.6 output are retained.

The positive control found AES-CBC. Exploratory calibration changed one source
form at a time:

| Control | Reported scanned files | Native AES-CBC asset |
| --- | ---: | --- |
| Literal key, direct return | 1 | Present |
| Literal key, assigned cipher | 1 | Present |
| Parameter key, assigned cipher | 1 | Present |
| RNG-derived key, assigned cipher | 1 | Present |
| Literal key, explicit backend keyword | 1 | Absent |
| Literal key, explicit positional backend | 1 | Absent |

The optional backend argument is accepted and unused by the inspected
[cryptography 46.0.3 constructor](https://github.com/pyca/cryptography/blob/46.0.3/src/cryptography/hazmat/primitives/ciphers/base.py#L78).
The paired observations therefore identify backend-argument sensitivity in
this pinned scanner image. They do not establish the internal root cause or the
behavior of every scanner release. The real pyca slices use explicit backend
arguments, which is relevant context, not a complete causal attribution for
every absent asset. No source was rewritten to improve native output.

The native summaries reported 3/3 matrix-nio, 2/2 pyAesCrypt, 4/4 SecretStorage
and 1/1 Ansible files scanned, with zero native crypto assets in these slices.
File counts are the native summary, not independent parser verification.
Four matrix-nio candidates use PyCryptodome, outside this tool's declared Python
library scope; eight pyca candidates overlap its documented library scope.
Native occurrences identify crypto construction sites, rather than our complete
ultimate-origin contract. No origin error, abstention or accuracy score is
assigned to the missing fields/zero assets. This is a reproducible integration
finding requiring validation before any publication comparison.

## Reference completeness and reserved data

Evaluation contract `key-origin-diagnostics-v0.3` separates resolved coverage
from judgeable semantic claims. Only complete reference sets can establish an
incorrect resolved set/modality or an unsupported partial category. An incomplete
reference yields an unjudgeable comparison, not a correct or incorrect answer.
Resolution mismatches, partial compatibility, missing claims and malformed
evidence have separate counters. Undefined rates remain `null`.

Two additional project snapshots, S3QL and Tahoe-LAFS, are reserved separately.
Only nominal candidate indexing was performed; no origin analyzer was run and
no proposed origin labels were created for them. The conservative selector found
one candidate across these snapshots. This is not a sufficient held-out sample;
eligibility/coverage and license classification still need review. Disjoint
project identities and frozen method/candidate fingerprints prevent silently
relabeling these as evaluated test results.

Review bundles contain unchanged source, licenses, a contract/schema and blank
annotation records. They withhold predictions and assistant proposals. A project
author's own check must be recorded as author review. No record has been marked
independently approved and no bundle has been sent to another person.

## Reproduce

```bash
python scripts/acquire-key-origin-corpus.py --fetch --root output/python-project-sources
python scripts/run-project-key-origin.py --source-root output/python-project-sources --backend ast-lite --out-dir output/project-ast
python scripts/observe-cbomkit.py --pull --source-root output/python-project-sources --out-dir output/cbomkit-native
python scripts/check-key-origin-freeze.py --snapshot-only
```

Use new result directories. The CI workflow contains full Python/JEP matrix,
read-only project/DFG and native CBOMkit invocations. Default freeze checking
refuses pending review with exit 2 and runs no evaluation. Method fingerprints
normalize CRLF to LF for portability; source-resource fingerprints remain exact
raw bytes. The [latest machine record](../../research/python-key-origin/project-development-observations.json)
retains final outputs/fingerprints and the limited scope of each experiment.

`scripts/capture-key-origin-checkpoint.py` regenerates the machine record from
completed matrix, AST project, CPG project and native CBOMkit result directories.
It checks current input fingerprints, candidate identities and the common exporter
JAR before capturing summaries and raw-artifact hashes. It never supplies reference
labels. Upstream source/code-bearing raw graphs remain in the result directories,
with provenance and attribution notices; the committed project summaries omit
their code and raw node identifiers.

The [method snapshot](../../research/python-key-origin/evaluation-freeze.json)
was created after the development runs and nominal reserved indexing. It is not
a preregistration. To deliberately create a successor after a method change, use
`python scripts/freeze-key-origin-methods.py --output <new-freeze.json>` and
preserve the previous snapshot. CI checks the current committed snapshot on both
operating systems. Review readiness is a separate check and remains pending.

## What the research questions currently establish

1. **Claim fidelity:** Designed examples expose concrete weaknesses in the legacy
   helper-name and assignment-order heuristics. The bounded policy represents
   explicit source sets and uncertainty. Its source-inspection proposals remain
   unreviewed, so no semantic accuracy estimate follows.
2. **Evidence policy:** All four development conditions emitted structurally
   checked records at the 27 fixed sites. Structural checks establish record/span
   consistency, not whether the origin inference is true. The legacy output lacks
   an equivalent origin-set/modality contract, preventing a fair numeric claim
   that the policy reduced semantic error over the legacy heuristic.
3. **Context contribution:** Under the shared bounded interpreter, AST CALLS
   authorized four additional complete answers over source-only, and Fraunhofer
   CALLS authorized two. These 27 authored examples do not demonstrate a CPG
   advantage. In the four real-project slices, neither context recovered a complete
   origin. Exported DFG paths show dependencies, including salt dependencies; no
   complete DFG origin-recovery method has been validated.

The final host suite passed **137 tests**, including real JVM-exporter checks;
three Python/JEP checks were skipped on the host and then passed in the Docker
runtime. The wheel and source distribution also built. These implementation
checks are separate from the research observations and independent annotation.

## Publication status

Before a paper result: establish independent source/candidate references, grow
and review reserved eligibility, refine coverage on development data, validate
the native scanner sensitivity and compare equivalent endpoints. A full DFG
ultimate-origin recovery method and a statistically defensible held-out study
have not been completed. The present results support a feasibility/limitations
discussion and concrete reproducible failures, not a detector-superiority claim.
This report can support a progress update or an early feasibility manuscript.
It is not a validated comparative research paper ready for submission.
