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

## Historical notes

Other guides and Turkish translations record earlier implementation stages.
They may contain superseded commands, coverage claims, timings or conclusions;
they do not establish accuracy, exporter availability or production readiness.
The current reading path above takes precedence.

Historical `results/` and root `result.json` files are local outputs, not a
versioned evaluation corpus. They remain on existing machines when removed from
Git tracking; repository cleanup does not rewrite history or delete local runs.
