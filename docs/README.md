# Documentation

Start with the [project README](../README.md). The current reading path is:

1. [Research scope and evaluation](RESEARCH.md): hypotheses, annotations and metrics.
2. [Reproducibility](REPRODUCIBILITY.md): local demo and exporter setup.
3. [Architecture](en/architecture.md): runtime and evidence boundaries.
4. [Custom schema](en/schema.md): fields and unknown/null semantics.
5. [Code map](en/code-map.md): module responsibilities.
6. [Roadmap](ROADMAP.md): research milestones.
7. [Contributing](../CONTRIBUTING.md): installation and checks.
8. [Validation snapshot](VALIDATION.md): checks actually performed and their limits.
9. [Literature and language decision](research/LITERATURE-2026-10-27.md): overlap, artifact checks and the Python scope.
10. [Python feasibility pilot](../research/python-key-origin/README.md): source cases and reproducible observations.
11. [Key-origin contract and review workflow](../research/python-key-origin/CONTRACT.md): implemented subset, evidence checks and review-gated diagnostics.
12. [Development checkpoint](research/DEVELOPMENT-2026-10-27.md): observed backend differences, checks and remaining research work.
13. [Expanded development experiment](research/EXPANDED-2026-10-27.md): 24 common sites, source-only/AST/CPG conditions, provisional checks and an external-tool feasibility run.
14. [Current project and DFG study](research/PROJECT-STUDY-2026-10-27.md): 27 designed cases, pinned real-source slices, native CBOMkit controls and reserved evaluation snapshots.
15. [Expanded source population](../research/python-key-origin/expanded-2026-10-30/README.md): predeclared projects, 19 development/33 reserved nominal sites and pending review.
16. [First human source review, Turkish](research/USER-REVIEW-TR.md): four-case author training and the independent-review workflow.
17. [Method integrity audit](research/METHOD-AUDIT-2026-10-30.md): source semantics, failure isolation, review auditing and remaining publication gates.

## Historical notes

Other guides and Turkish translations record earlier implementation stages.
They may contain superseded commands, coverage claims, timings or conclusions;
they do not establish accuracy, exporter availability or production readiness.
The current reading path above takes precedence.

Historical `results/` and root `result.json` files are local outputs, not a
versioned evaluation corpus. They remain on existing machines when removed from
Git tracking; repository cleanup does not rewrite history or delete local runs.
