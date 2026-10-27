# Research scope and evaluation protocol

## Motivation

An API inventory can identify a cryptographic operation without establishing its
application purpose or parameter origins. CryptoGraph investigates whether
structured program evidence can narrow that gap.

**Research question:** How can cryptographic usage in source code be identified,
contextualized, and represented in an explainable, CBOM-compatible format beyond
simple API matching?

The proposed contribution is a method of representing and evaluating
context supported by evidence. It remains a hypothesis to validate.

## Evidence boundaries

| Category | Example | Interpretation |
| --- | --- | --- |
| Observed | Source location, matched call, literal parameter, exported edge. | Inspectable input/backend information; parser correctness still matters. |
| Derived | Algorithm normalization, local origin, incoming source-to-sink path. | Transformation of observations under assumptions that require checks. |
| Hypothesized | Application intent or higher-level security purpose. | Interpretation requiring independent labels or contextual review. |
| Unresolved | Unknown key origin or unavailable flow path. | Insufficient evidence; it does not imply safety. |

This is a review convention, not a claim that every field already carries a
machine-readable category. Intent strings and confidence values are heuristic.
Call ancestry is not an interprocedural variable-flow proof. `unknown` denotes
an unresolved applicable field; `null` denotes a field considered inapplicable.

## Planned comparison

Hold input programs, API mappings and annotation policy constant:

- **A: API-only.** API identity and statically visible parameters.
- **B: Graph-enriched.** A plus local origins, call relations and directed flow evidence.
- **C: Evidence-grounded intent.** B plus higher-level inference, potentially an LLM, supplied with a bounded evidence record.

A clean ablation interface and an external LLM integration are not implemented.
Legacy and v2 matchers differ in more than context; they are not valid A/B
experimental conditions without further controls.

Hypotheses to test:

1. Context improves material-origin classification over A.
2. Directed, sink-specific evidence reduces unsupported flow claims.
3. C improves intent classification when evidence is sufficient and can abstain
   when application purpose is not recoverable from source.

Existing regression tests do not establish these hypotheses.

## Annotations and measurements

Start with manually annotated positive, negative and ambiguous cases. Include
aliases, wrappers, parameter forwarding, reassignment, unrelated graph paths,
cross-function flow, and runtime configuration. Include identical APIs used for
different purposes and examples whose purpose is intentionally unknowable.

Each label should record source revision, file/span, operation, algorithm and
parameters, material origins, contextual role, supporting evidence and an explicit
unknown option. Record disagreements and adjudication, using independent review
where possible. Preserve provenance and redistribution terms for external code.
Never derive ground truth from CryptoGraph's own output.

Report detection precision/recall/F1 separately from origin and intent
classification. Define source-span/operation matching before experiments. For
context, report per-class errors, abstention rate and accuracy among answered
cases. Report unsupported evidence claims, parse coverage, fallback rates and
failed jobs alongside accuracy. Empty and failed scans remain in the accounting.

For LLM experiments, freeze model/provider version, prompt, sampling settings,
evidence budget and responses. Split by project to limit repeated-code leakage.
Record environments for runtime/resource measurements; anecdotal scans are not
performance results.

## Current validation and threats to validity

Tests cover selected sample detection, upstream traversal, unrelated flow,
unknown-algorithm risk, partial failures, conversion structure and baseline
labels. Mapping parity tests check configuration predicates; they do not measure
recall or prove that every rule triggers end to end.

The [reproduction demo](REPRODUCIBILITY.md) exercises the lightweight path.
The [validation snapshot](VALIDATION.md) records an exporter build and a controlled
Java case. Wider frontend coverage, interprocedural bindings and graph
completeness need independent checks. The hybrid converter declares version 1.5
while emitting crypto-specific fields and custom analysis data; schema conformance
is not established.

Controlled examples can overestimate coverage. Pattern scanners can confuse
names, strings, macros and declarations with calls. Local heuristics can miss
reassignment and cross-function dependencies. Source may not reveal intent or
runtime configuration. Heuristic PQC labels do not demonstrate quantum safety.
