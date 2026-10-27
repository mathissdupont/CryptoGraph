# Validation snapshot - 27 October 2026

This snapshot describes local changes on branch `chore/research-readiness`, based
on commit `f4515c4221adf3edab27cecea508be5793eeb8a5`. The changes were uncommitted
when checked; the base commit alone does not contain the fixes described here.
This is implementation validation, not a research evaluation or release.

## Checks performed

| Check | Observed result | Scope |
| --- | --- | --- |
| Complete suite with real exporter enabled | 36 passed | Windows, Python 3.14.2, host Java 17. |
| Bundled exporter Docker build | Successful `shadowJar` build | Gradle 8.12/JDK 17 image, bundled CPG 9.0.2 dependencies. |
| Java source to CBOM | Cipher call detected; AES/ECB mode retained and elevated risk reported. | One controlled Java example; no interprocedural correctness claim. |
| Unsupported exporter input | Nonzero exporter failure, surfaced as `CpgLoadError` in strict mode. | Text input with no supported source files. |
| Streamlit interaction | Scan, filter rerun, baseline labeling and result persistence passed. | AppTest with local Python input; no external repository or browser visual assessment. |
| Distribution build | Wheel and source distribution built. | Configurations bundled; sample/reproduction sources included in sdist. |
| Installed-wheel smoke | Scan and HTML report succeeded outside the checkout. | Separate virtual environment; no editable source paths. |
| README repository/labeling commands | Completed on Windows. | Local Python samples and deterministic baseline labels. |

The exporter tests are opt-in. Set `CRYPTOGRAPH_TEST_EXPORTER` to an absolute path
to the built JAR and run `python -m pytest -q`. Without this variable, the two
real-JVM tests skip. The UI test skips when Streamlit is not installed; install
`.[dev,ui]` to include it. CI now defines separate package, UI and exporter jobs
as well as Windows/Linux Python 3.12/3.14 regression jobs. Those remote jobs have
not been run for this local branch.

## Reliability fixes exercised

- Both matchers accept flat and per-language mapping schemas.
- Absolute CBOM output paths honor an optional HTML report.
- Installed defaults find bundled configuration and create runs under the working directory.
- Strict mode rejects Ruby substitution, empty C/C++ call-graph fallback and legacy source-boundary exporter results.
- Frontends register using their actual fully qualified CPG class names.
- The exporter propagates analysis failures instead of returning a source-boundary fallback as success.
- Source receiver text remains available for syntactic matching when CPG reports an unresolved member name; it is not labeled semantic resolution.
- Literal Java cipher transformations retain algorithm, mode and padding in the final CBOM.
- Baseline labeling writes UTF-8 and does not require Unicode progress symbols on the console.
- Viewer results survive reruns and consume the structured risk field.

## Remaining validation

No labeled corpus, precision/recall results, calibrated confidence or evidence of
improvement over API-only analysis is supplied. Full runtime Docker image setup,
Python/JEP operation, other frontends, mixed projects, cross-function bindings and
data-flow completeness need separate evaluation. The successful Java smoke test
does not establish those properties. CycloneDX schema conformance and actual LLM
provider integration remain outstanding.

Historical generated files were removed from Git tracking, with all 1,084 files
and their 73,359,291 bytes retained locally. Git history was not rewritten.
