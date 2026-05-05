# CryptoGraph Language Roadmap

This roadmap is optimized for the most common production languages and uses Fraunhofer CPG whenever the backend is available for a language. The goal is a single CBOM schema and a single LLM-labeling dataset across all supported languages.

## Priority Order

1. Java
2. Kotlin
3. JavaScript
4. TypeScript
5. C#
6. C++

Ruby is supported through a lightweight fallback backend today and can be expanded later, but it is not part of the primary roadmap above.

## Backend Strategy

Use the strongest available backend first:

| Language | Preferred Backend | Fallback |
|---|---|---|
| Java | Fraunhofer CPG | language-lite fallback only if needed |
| Kotlin | Fraunhofer CPG | Java-compatible fallback where possible |
| JavaScript | Fraunhofer CPG | lightweight JS/TS fallback |
| TypeScript | Fraunhofer CPG | lightweight JS/TS fallback |
| C# | Fraunhofer CPG if supported | C#-specific lightweight fallback |
| C++ | Fraunhofer CPG if supported | C/C++ lightweight fallback |

Fraunhofer is always preferred when it can emit a valid graph for the target language and repository.

## Phase 1 - Make Fraunhofer the default for the main languages

Goal: make Java, Kotlin, JavaScript, TypeScript, C#, and C++ scan through the Fraunhofer exporter whenever possible.

Work items:

- Verify exporter coverage per language against a real repository for each target language.
- Confirm graph output includes function nodes, call nodes, argument nodes, and usable dataflow edges.
- Normalize exporter output into the existing `NormalizedGraph` shape.
- Add regression tests for each language family.

Suggested validation repos:

- Java: Spring Framework or a small Maven sample
- Kotlin: a Gradle/Kotlin sample or Android-style library
- JavaScript / TypeScript: `expressjs/express` and a TS-heavy repo
- C#: a small .NET sample repository
- C++: a small OpenSSL or crypto-heavy C++ sample

## Phase 2 - Improve fallback analyzers where Fraunhofer is not enough

Goal: preserve useful CBOM output even when a full CPG is not available.

Work items:

- Keep Python `ast-lite` for Python.
- Keep Ruby `ruby-lite` for Ruby.
- Add a minimal fallback only when Fraunhofer is unavailable or insufficient.
- Ensure every fallback emits the same core CBOM fields:
  - `crypto_metadata`
  - `usage`
  - `context`
  - `flow`
  - `control`
  - `graph_context`
  - `risk`
  - `rules`
  - `evidence`

## Phase 3 - Normalize CBOM across languages

Goal: one language-agnostic CBOM schema regardless of backend.

Work items:

- Merge per-language assets into a single schema.
- Keep language-specific metadata in a bounded `context` or `metadata` field.
- Normalize algorithm/mode/provider naming across languages.
- Preserve evidence summaries for LLM labeling.
- Export a flat JSONL dataset for each asset.

## Phase 4 - LLM Labeling Layer

Goal: make every CBOM asset usable for human review and LLM labeling.

Work items:

- Build a stable JSONL shape for labels.
- Feed `crypto_metadata`, `usage`, `context`, `flow`, `control`, `rules`, and `evidence_summary` to the LLM layer.
- Keep deterministic findings and LLM labels separate.
- Add prompts for language-specific crypto conventions.

## Phase 5 - Testing and Release Gates

Goal: prevent regressions as language support expands.

Work items:

- Add a smoke test per primary language family.
- Add multi-language repository scans as CI regression tests.
- Validate that merged CBOMs are non-empty when crypto is present.
- Validate that Fraunhofer output falls back cleanly when unavailable.

## Recommended Implementation Order

1. Java + Kotlin together, because they share the JVM ecosystem and Fraunhofer integration path.
2. JavaScript + TypeScript together, because they share a large amount of API and parser overlap.
3. C# next, because the .NET ecosystem is common and deserves a dedicated path.
4. C++ last, because exporter/parser support is usually the hardest to stabilize.

## What Success Looks Like

- A user pastes a repo URL into the UI.
- CryptoGraph detects the languages.
- Fraunhofer is used wherever it is available and trustworthy.
- Fallback analyzers fill gaps only where needed.
- The output is one consistent CBOM and one consistent JSONL dataset.
- LLM labeling can run on top without special-case logic per language.
