# Notes

- Fraunhofer CPG Python frontend requires JVM-side setup and `jep`.
- Docker is the preferred execution path for consistent Java/Python compatibility.
- Full CBOM compliance is intentionally deferred until the detection model stabilizes.
- The exporter now attempts real Fraunhofer `TranslationManager` traversal first. In the current Docker image, the Python frontend reaches JEP but aborts inside the native Java/Python boundary, so the Python CLI isolates the crash in a subprocess and falls back to `ast-lite`.
