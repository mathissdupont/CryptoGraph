# Fraunhofer CPG Integration for CryptoGraph

This document describes how to prepare and use the Fraunhofer CPG exporter with CryptoGraph so you can generate full CPG-backed CBOMs for the languages supported by CPG.

Quick summary:

- CryptoGraph expects a Fraunhofer exporter JAR and reads it via the environment variable `CRYPTOGRAPH_FRAUNHOFER_EXPORTER`.
- If the exporter is not available, CryptoGraph falls back to the lightweight `ast-lite` Python extractor (limited to Python semantics).
- Building the Fraunhofer CPG may require: Java (JDK 17+), Gradle, native toolchains (for C/C++), and language-specific helpers (JEP for Python, libgoast for Go).

Recommended automated helper:

```
./scripts/build_fraunhofer_exporter.sh /tmp/cpg python,java,go
# After it completes, set the path it prints:
export CRYPTOGRAPH_FRAUNHOFER_EXPORTER=/tmp/cpg/path/to/exporter.jar
```

Manual steps (if prefer):

1. Clone the CPG repository:

```bash
git clone https://github.com/Fraunhofer-AISEC/cpg.git
cd cpg
cp gradle.properties.example gradle.properties
# Edit gradle.properties and enable the frontends you need, e.g.:
# enablePythonFrontend=true
# enableGoFrontend=true
# enableJavaFrontend=true
./gradlew assemble
```

2. Locate the exporter JAR (search for `exporter` or `cpg` jars under `build/` directories) and set the environment variable:

```bash
export CRYPTOGRAPH_FRAUNHOFER_EXPORTER=/abs/path/to/exporter.jar
```

3. Run CryptoGraph normally; the `fraunhofer` backend will invoke the exporter as a subprocess to produce a normalized graph JSON, which CryptoGraph will ingest.

Notes and caveats:

- Building CPG is heavy and may fail on Windows. Use Linux or WSL for best results.
- Some language frontends require system dependencies (Eclipse CDT for C++, libgoast for Go, jep for Python). See the CPG README.
- If the exporter is unavailable, CryptoGraph will fall back to `ast-lite` for Python. Other languages will not be analyzed deeply without CPG.

If you'd like, CryptoGraph can attempt to build CPG automatically (see the `--build-cpg` option for `scan-repo`), but this is best run on a Linux/WSL host with Java/Gradle installed.
