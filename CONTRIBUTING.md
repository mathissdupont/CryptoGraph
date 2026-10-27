# Contributing

Changes should make the analysis easier to inspect and evaluate, with explicit
assumptions and reproducible evidence.

## Development

Create and activate a Python 3.12+ virtual environment, then from the root:

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
python scripts/reproduce.py --out-dir output/my-demo
python -m build
```

The optional UI uses `python -m pip install -e ".[ui]"`. Core installation does
not need JEP or Java. See [exporter setup](docs/REPRODUCIBILITY.md) for separate
JVM/Docker dependencies. CI runs the full suite and a wheel smoke scan outside
the checkout to catch editable-only configuration paths.

## Review expectations

- The active CLI uses `crypto_matcher_v2.py` and `cbom_builder_v2.py`.
- Add focused regressions for behavioral bugs, including negative/unknown cases.
- Mapping entries do not establish language support; state the parser tested.
- Preserve failed-job reporting, backend provenance and unresolved fields.
- Do not present heuristic confidence as measured probability.
- Keep current docs aligned with commands and evidence semantics.

Keep scans, clones, JARs, caches and secrets out of Git. Use `output/` or `results/`
for local runs. Do not execute intentionally insecure samples as applications.
External evaluation inputs need revision, provenance and reuse terms.

PRs should explain concrete before/after behavior, checks and remaining limits.
Mark exporter, UI or standards checks unverified when not run. Do not select a
license or add personal acknowledgments on someone else's behalf.
