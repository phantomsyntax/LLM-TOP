# LLM-TOP (LLM Token-Optimized Protocol)

LLM-TOP is a dense, token-optimized protocol layer for multi-agent LLM orchestration. It replaces
conversational framing with strict key-value markers and moves capability tokens out of the
generation stream, so an agent's output carries instructions rather than credentials.

Measured with a real `cl100k_base` (tiktoken) tokenizer, LLM-TOP costs **~73% fewer tokens than the
OpenAI `tool_calls` envelope on output tool-call turns**, and **~22–54% fewer than JSON
transcriptions of the same frame**, depending on how the JSON is formatted. Both figures are
reproducible from `benchmarker_real.cpp` in this repository — see
[Measurement](#empirical-measurements) for what each one does and does not claim.

---

## Key Features

1. **Out-of-Band Host Session Proxy Mode**: With `set_out_of_band_proxy(true)`, capability grants
   live in the host session keyed by `agent_id`, so no bearer token appears in the model's output.
   This is primarily a **credential-exposure** control; the token saving is a side effect of not
   emitting a ~200-token JWT, and any format gets the same benefit.
2. **Thread-Safe Idempotency & Replay Protection**: An in-memory `IdempotencyStore` tracks executed
   `(agent_id, reqid)` tuples under a mutex, rejecting duplicates with `ERR:replay_detected`.
   Entries expire on a TTL, and a saturated store **fails closed** rather than evicting live
   entries — a flood cannot age out a legitimate request to make room for a replay.
3. **Path Confinement & Scope Globbing**: Scope evaluation normalizes path segments and refuses
   any resource that escapes the working root, independent of what the granted scope says.
   Supports single-level (`*`) and multi-depth (`**`) directory scopes.
4. **HMAC-SHA256 Capability Tokens, with a Verifier Registry**: Ships HMAC-SHA256 only. The
   algorithm named in the JWT header binds to a registered verifier, so `alg` cannot select a
   weaker path. A host needing asymmetric verification registers its own verifier backed by its own
   crypto library — **this project does not implement one, and does not hand-roll curve
   arithmetic in the trust boundary**.
5. **Deterministic Lexer & Escape-Aware Parsing**: A quote-aware state-machine lexer handles
   escaped characters (`\"`, `\n`) and isolates nested string payloads.
6. **Structured Recovery & Self-Healing**: In Tolerant Mode syntax errors are captured in a
   `diagnostic` buffer, enabling recovery-instruction generation and `FALLBACK:json` emission
   without halting. Self-healed statements are held separately and schema-validated; the
   middleware rejects them unless the host explicitly opts in.

> **What `CHK` is for.** The `CHK` header digests the full frame, including the identity header,
> with its own field zeroed. It is **unkeyed**, so it detects truncation and corruption — it is not
> an authentication mechanism, because anyone modifying a frame can recompute it. Authentication
> comes from capabilities.
>
> A model cannot compute SHA-256 over its own output, so **an LLM-generated frame never carries a
> valid `CHK`**. Producers stamp it with `stamp_chk()` (`chk.hpp`); hosts whose producer and
> verifier are the same process can turn the check off with `set_verify_chk(false)`, since a digest
> compared against memory that never crossed a boundary detects nothing. Verification is **on by
> default**.

---

## Project Architecture

Header-only C++20. No runtime dependencies.

- `parser_v2.hpp`: Lexer and parser state machine.
- `middleware.hpp`: Execution arbiter — JWT validation, capability authorization, path confinement,
  out-of-band session proxy mode, `IdempotencyStore`.
- `schema_validator.hpp`: Per-role statement schema validation.
- `chk.hpp`: Producer-side integrity helpers — `stamp_chk()` / `compute_chk()`.
- `tokenizer.hpp`: Self-contained `cl100k_base` (tiktoken) BPE tokenizer. ASCII-only by design, and
  it **rejects** non-ASCII input rather than silently mis-counting it.
- `binary_encoder.hpp`: Loss-free binary serializer for the **host↔host** leg (see caveat below).
- `fallback_recovery.hpp`: Recovery-plan generation for corrupted payloads.

**Tools and tests**

- `llmtop_eval.cpp`: Measures a payload — real BPE token count plus parse/schema validation —
  and emits one line of JSON. Every published figure traces back to this or `benchmarker_real`.
  `--stamp` writes the frame back out with a correct `CHK`, which is how a host makes
  LLM-generated output satisfy the integrity check.
- `run_compliance_eval.ps1`: Measures how often a model emits a *valid* payload, against a
  free-text JSON control held to equivalent strictness. Reports Wilson intervals, and excludes
  transport failures and truncated generations from the denominator rather than scoring them as
  format failures.
- `sample.llmtop` / `sample_corrupt.llmtop`: a valid frame (stamped, passes schema validation) and
  a deliberately damaged one for demonstrating tolerant-mode recovery.
- `benchmarker_real.cpp`: Token measurements across multi-agent scenarios.
- `fuzzer.cpp`: Randomized mutation fuzzing across the parser, middleware, JWT/base64 decode, and
  binary decoder, asserting output invariants rather than mere absence of exceptions.
- `run_live_eval.ps1`: Live model evaluation harness (PowerShell; token counts come from
  `llmtop_eval`, not character lengths).
- `test_*.cpp`: 349 runtime checks across 9 CTest suites.

---

## Building and Testing

```bash
cmake -B build
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

The suite must also pass in Release. Test assertions are ordinary function calls
(`test_harness.hpp`), **not** `assert()`, so they are not compiled out under `NDEBUG`:

```bash
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Current state: **9/9 suites, 349 checks, passing in both Debug and Release**; fuzzer clean over
3,211 iterations.

`benchmarker`, `benchmarker_real`, `llmtop_parse`, and `llmtop_eval` are build targets rather than
tests — they measure and report, they do not assert. Run them directly.

---

## Empirical Measurements

All figures below are reproduced by running `benchmarker_real` from this repository. Sign
convention throughout: **positive means LLM-TOP used fewer tokens.**

### 1. Output tool-call turns vs the OpenAI `tool_calls` envelope

This is the comparison against a format models actually emit, where the JSON alternative nests a
JSON-escaped `arguments` string inside a `tool_calls` object.

| Case | LLM-TOP | OpenAI `tool_calls` | Reduction |
| :--- | :---: | :---: | :---: |
| Single tool call | 8 | 42 | 81.0% |
| Two arguments | 12 | 45 | 73.3% |
| Three calls in one turn | 28 | 102 | 72.5% |
| **Median** | | | **73.3%** (range 72.5%–81.0%) |

### 2. Full context frames vs JSON/YAML transcriptions

| Baseline Format | Median Reduction | Range |
| :--- | :---: | :---: |
| Pretty-printed / verbose JSON | 53.8% | 24.6% – 55.4% |
| Compact JSON (no spaces) | 23.8% | 8.0% – 27.0% |
| Minimal JSON (single-character keys) | 21.8% | 7.0% – 25.5% |
| YAML | 30.2% | 10.7% – 35.3% |

> **Baseline provenance.** These four baselines are the LLM-TOP frame re-encoded — they measure
> LLM-TOP's own AST shape expressed as JSON or YAML, not a format any API speaks. They answer
> "how much does the syntax cost?", not "how much would I save by switching?". Table 1 answers the
> second question.

### 3. Auth mode and format, separated

The previously published "−75% on tool calls" changed two variables at once: it compared an LLM-TOP
frame with **no** capability token against a JSON frame carrying a **full JWT**. Measured
separately:

| What varies | Reduction |
| :--- | :---: |
| **Auth mode only** — LLM-TOP in-band JWT → out-of-band | **73.6%** |
| **Format only** — minified JSON → LLM-TOP, both out-of-band | **22.7%** |
| *Both at once (the old comparison)* | *75.5%* |

Nearly all of the headline saving is the first row: **not emitting a ~200-token JWT**. That is a
real and worthwhile result, but it is a property of out-of-band capability handling, which any
serialization format can adopt — not of LLM-TOP's syntax.

### Withdrawn claims

Two previously published figures do not reproduce and have been withdrawn:

- **"+25.9% net savings vs minified JSON"** — produced by a character heuristic
  (`word_chars/4 + punct_chars/2`) in a Python harness that has since been deleted, not by a
  tokenizer. The nearest honest equivalent is the **22.7%** format-only row above.
- **"+67.3% over pretty-printed JSON"** — same origin, and it also contradicted this project's own
  benchmark table, which has consistently reported **53.8%**.

The live-model endpoint table (latency, tokens/sec, speculative-decoding acceptance rate, "100%
Validated") has also been removed. Latency and throughput are properties of a vendor's serving
stack rather than of this protocol, the compliance column was a hardcoded string literal, and the
whole table rested on n=2 requests per model. `run_live_eval.ps1` can regenerate honest versions of
these measurements — it now counts real tokens and reports measured validity — but the results are
not republished here until the sample size justifies it.

### Binary encoder scope

`binary_encoder.hpp` compresses the **host↔host** leg only. A model emits and consumes text, so
binary framing cannot reduce LLM token cost; it reduces bytes between cooperating hosts that have
already parsed the frame. Any compression figure for it belongs to transport, not to inference
billing.

---

## License

This project is licensed under the [MIT License](LICENSE) — see the LICENSE file for details.
