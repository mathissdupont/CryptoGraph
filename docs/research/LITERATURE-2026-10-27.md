# Literature screening and language decision - 27 October 2026

This is a targeted scoping review, not a systematic literature review or proof of
novelty. Searches combined Python/Java cryptographic API misuse, CBOM, context,
key origin, evidence/provenance, abstention and selective prediction. Sources were
screened by task, extracted evidence, evaluation unit and artifact availability.
Publisher/author pages and primary repositories were preferred. Tools were not
all reproduced, and reported performance values are not compared across corpora.

## Language decision

**Select Python for the first study.** This is a feasibility and measurement
decision, not a claim that Python has more cryptographic usage than every other
language. No comparable global measurement establishing that ranking was found
in this screening. Language popularity and misuse prevalence in selected samples
are different measurements.

| Criterion | Python | Java |
| --- | --- | --- |
| Current project investment | AST backend, controlled samples and context code are Python-oriented. | One real exporter cipher smoke test, with much less local corpus coverage. |
| Technical feasibility checked locally | Full Docker Python/JEP/CPG path runs; eight key-origin probes compared with AST-lite. | Bundled exporter and a controlled JCA example run. |
| Relevant prior evaluation | LICMA, Cryptolation/PyCryptoBench, CryptoPyt, CRYPTBARA. | CryptoAPI-Bench, CryptoGuard, CogniCrypt/CrySL and MASC. |
| Study difficulty | Aliases, wrappers, shadowing and dynamic bindings demand explicit scope and unknowns. | Mature comparison ecosystem; switching requires rebuilding much of this project's evaluation path. |

The table reports local implementation facts and research-design judgments. It
does not rank language-wide cryptographic usage or detector performance.

## Closely related work

| Primary source | What overlaps | Consequence for CryptoGraph |
| --- | --- | --- |
| [Python Crypto Misuses in the Wild, ESEM 2021](https://arxiv.org/abs/2109.01109) | Static analysis across Python crypto APIs and an empirical project study. | Python is a legitimate study population; sample prevalence is not a global language comparison. |
| [Methods and Benchmark for Detecting Cryptographic API Misuses in Python, TSE 2024](https://doi.org/10.1109/TSE.2024.3377182) | Cryptolation, interprocedural variable inference and PyCryptoBench; the paper reports 1,836 test cases. | Neither Python support nor tracing parameters through functions is a new contribution. Existing misuse labels do not automatically supply key-origin or evidence-validity labels. |
| [CryptoPyt, ACSAC 2024 artifact listing](https://www.acsac.org/2024/program/artifacts/) | Python cryptographic misuse detection with static taint analysis. | Include in the comparison screening; the full artifact and paper still need reproduction/read-through before method-level comparisons. |
| [CRYPTBARA, ASE 2025](https://ssp.korea.ac.kr/assets/papers/ASE25.pdf) | Static intra/interprocedural dependencies supplied to LLM-based misuse detection. Its discussion covers indirect/dynamic calls and ambiguous labels. | Context extraction and a CPG/LLM combination are not sufficient novelty. Evaluate a different endpoint and explain how its labels differ. |
| [MASC extension, 2026](https://arxiv.org/abs/2107.07065v6) | Mutation-based systematic evaluation of crypto detectors. | Mutating aliases, wrappers or placement is established practice; new transformations alone are insufficient without a distinct measurement or finding. |
| [PQCA CBOMkit architecture, 2026](https://pqca.org/blog/2026/pqca-cbomkit-architecture/) | AST detection, semantic mapping, detected/inferred/enriched origin metadata, evidence and CBOM output. | Recording evidence or distinguishing observed and inferred metadata is already present. Metadata origin is distinct from the origin of a key value. |
| [Hidden Ciphers and Where to Find Them, 2026](https://arxiv.org/abs/2608.04857) | Static asset classification and assessment with CBOM-oriented output and empirical evaluation. | Asset inventory plus risk assessment is already studied. This screening used the abstract/preprint description; it is not a full replication. |
| [Checking Cryptographic API Usage with Composable Annotations, PEPM 2018](https://doi.org/10.1145/3162071) | Security properties attached to values for cryptographic API checking in JavaScript. | Value provenance and cryptographic preconditions have earlier foundations outside Python. |
| [Noise-free Selective Classification, JMLR 2010](https://jmlr.org/papers/v11/el-yaniv10a.html) | Reject options and the risk/coverage trade-off. | Abstaining is not novel. Lower error after rejecting more cases must be assessed together with coverage. Its learning-theory guarantees do not transfer automatically to our analyzer. |
| [Runtime Cryptographic Evidence to Bounded Assurance Verdicts, 2026](https://doi.org/10.3390/computers15100659) | Runtime evidence, provenance and ACCEPT/REJECT/REVIEW outcomes in controlled cryptographic workloads. | An uncertainty/review state is not new. Our proposed static source-origin endpoint differs from runtime conformance and policy appraisal. Screening was limited to indexed publisher material. |
| [Calibrated and cost-sensitive vulnerability alert governance, 2026](https://doi.org/10.1016/j.array.2026.101061) | Calibration, review decisions and uncertainty-aware vulnerability triage. | Generic confidence calibration/review is occupied territory; this study does not propose a new calibration method. Screening was limited to indexed publisher material. |
| [PQCensus primary repository](https://github.com/XiantingWu/PQCensus) | A Python AST inventory tool describes purpose evidence and abstention on unknown purpose. | Treat as a close engineering comparator; its README claims and author-curated benchmarks have not been independently reproduced here. Do not claim the first uncertainty-aware inventory. |

## Artifact feasibility

- [CRYPTBARA's source repository](https://github.com/choseogyeong/CRYPTBARA) and
  [archived artifact](https://zenodo.org/records/15561335) are discoverable. Source
  inspection/reproduction, license review and benchmark acquisition remain to do.
  No LLM calls were made during this screening.
- The originally cited `franceme/pycryptobench` location returned 404. The public
  [cryptolation/PyCryptoBench](https://github.com/cryptolation/PyCryptoBench)
  repository exposed only a README in this check. The published case count is
  therefore not a verified local dataset count. Recover the intended release or
  archive before promising a ready-to-run PyCryptoBench baseline.
- [Cryptolation's public code](https://github.com/franceme/cryptolation) is
  discoverable; equivalence to the TSE study version is not established.
- [Bandit's documented blacklist checks](https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html)
  are useful detection context, but do not expose an equivalent key-origin claim
  contract. Missing fields must not be converted into false claims for scoring.
- CBOMkit is a candidate on overlapping `cryptography` APIs. The pilot's current
  PyCryptodome cases alone would not be a fair cross-tool evaluation.

## Judgment

Follow-up implementation and reproduction notes are recorded in the
[expanded checkpoint](EXPANDED-2026-10-27.md). The corpus now includes pyca
constructors for future shared-API comparisons. A pinned PQCensus audit passed
SHA-256/RSA controls but emitted no findings for the 24 AES examples; inspection
of that revision found no AES-constructor classifier or equivalent ultimate
key-origin contract. It remains related engineering work, rather than a scored
origin comparator for these examples. This does not reproduce its own benchmarks.

The broad question "can graphs/context/evidence improve crypto analysis?" is too
close to existing work to use as the contribution claim. A narrower empirical
study of **key-origin claim fidelity, evidence validity and coverage under explicit
unknowns in Python** is worth a pilot. Its novelty and utility remain hypotheses.
The pilot must test source-specific claims and compare appropriate baselines;
finding simple bugs only in CryptoGraph would support engineering repairs, not
by itself a general research result. The updated protocol defines decision gates.
