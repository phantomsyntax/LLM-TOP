# Test Plan and Results for LLM-TOP

## Overview

This document records what is actually tested, and what each result does and does not establish.

Every assertion in the suite uses `test_harness.hpp` (`CHECK`, `CHECK_EQ`, `CHECK_CONTAINS`,
`CHECK_THROWS_WITH`), which are ordinary function calls. They are **not** `assert()`, so `NDEBUG`
does not compile them out and a Release run verifies the same conditions as a Debug run. This
matters: the suite previously used `assert()` throughout and therefore evaluated nothing in Release
while still reporting 9/9 passing.

**Current state:** 9/9 CTest suites, **349 runtime checks**, passing in both Debug and Release.

| Suite | Checks |
| :--- | :---: |
| `middleware_tests` | 197 |
| `core_tests` | 51 |
| `binary_tests` | 33 |
| `recovery_tests` | 25 |
| `tokenizer_tests` | 18 |
| `schema_tests` | 14 |
| `integration_tests` | 6 |
| `harness_selftest` | 5 |

`harness_selftest` exists to keep the above honest: it deliberately fails two checks, confirms the
harness counted both, then resets. If assertions ever stop being evaluated, that suite fails first.

## 1. Parser & Multi-Surface Fuzzing

- **Goal**: Find brittle parse paths and boundary handling under corrupted input.
- **Implementation**: `fuzzer.cpp` mutates canonical payloads (swap, truncate, inject corrupt ASCII)
  across four surfaces: the parser, the middleware authorization path, JWT/base64url decoding, and
  the binary decoder. Each phase asserts output invariants — not merely that no exception escaped.
- **Result**: [PASS] **3,211 iterations, 0 crashes, 0 unhandled exceptions.**
- **Limitation**: This is randomized mutation fuzzing without coverage feedback, run for a fixed
  iteration count. It demonstrates robustness against the mutations it generates. It is not a proof
  of memory safety and is not a substitute for a sanitizer build.

## 2. Middleware & Capability Security

- **Goal**: Validate capability tokens, scope matching, path confinement, out-of-band proxy auth,
  and replay protection.
- **Implementation**: `test_middleware.cpp` covers signature tampering, algorithm/verifier binding,
  claim extraction against nested-JSON confusion, single-level vs multi-depth glob semantics, path
  escape refusal, idempotency expiry and capacity behavior, plan-argument sanitization, and CHK
  coverage of the identity header.
- **Result**: [PASS] 197 checks.
- **Scope note**: Only **HMAC-SHA256** is implemented and therefore only HMAC-SHA256 is tested.
  Earlier revisions of this document claimed an Ed25519 signature test; no such test existed, and
  no Ed25519 implementation exists. Hosts needing asymmetric verification register their own
  verifier.

## 3. Binary Encoding & Tokenizer

- **Goal**: Verify loss-free binary serialization and BPE tokenizer precision.
- **Implementation**: `test_binary.cpp` and `test_tokenizer.cpp`.
- **Result**: [PASS] `OP_HR` opcode round-trips; tokenizer reproduces exact `cl100k_base` token ids
  for known vectors.
- **Tokenizer specifics** — the measurement instrument is validated before any figure is derived
  from it:
  - Exact known-vector ids (`hello`, `hello world`, `tiktoken is great!`).
  - Hand-derived pre-token boundaries across protocol punctuation (`:` `;` `=` `[` `]` `/` runs and
    digit grouping), where the hand-written cl100k pattern is most likely to be wrong.
  - A **differential check**: the fast priority-queue merge is compared against an independent,
    deliberately naive O(n²) reference merge over a corpus of protocol, JSON, and YAML payloads.
  - A **round-trip check**: `decode(encode(x)) == x`, which catches a pre-tokenizer that drops or
    duplicates input while still returning a plausible count.
  - Non-ASCII input is **rejected**, not approximated. The tokenizer is ASCII-specialized, and a
    silently wrong count is worse than a failed run.

## 4. Empirical Token Measurements

- **Goal**: Measure real BPE token counts across multi-agent scenarios.
- **Implementation**: `benchmarker_real.cpp`, plus `llmtop_eval` for measuring individual payloads.
- **Result**: See [README § Empirical Measurements](../README.md#empirical-measurements) for the
  current tables. Headline figures: **73.3% median reduction** on output tool-call turns versus the
  OpenAI `tool_calls` envelope, and **53.8% / 23.8% / 21.8% / 30.2%** versus verbose, compact,
  minimal JSON and YAML transcriptions of the same frame.
- **Withdrawn**: the previously reported **+25.9% vs minified JSON** and **+67.3% vs pretty-printed
  JSON** do not reproduce. Both came from a character heuristic in a deleted Python harness rather
  than from a tokenizer. The 67.3% figure also contradicted this project's own benchmark output,
  which has always reported 53.8%.

## 5. Live Model Evaluation

- **Status**: No live-model results are currently published.
- **Rationale**: The previous table reported end-to-end latency, generation speed, and
  speculative-decoding acceptance rates. Those measure a vendor's serving stack, not this protocol.
  Its "Output Compliance: 100% Validated" column was a hardcoded string literal in the harness, not
  a measurement, and the whole table rested on two requests per model.
- **Harness**: `run_live_eval.ps1` remains available and has been rebuilt to measure honestly — it
  counts real BPE tokens via `llmtop_eval` instead of string lengths, and it parses and
  schema-validates each response to report *measured* validity. It prints its own sample size and
  labels it as such. Results will be republished when the sample size supports a claim.
