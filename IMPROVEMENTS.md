# LLM-TOP Protocol: Architecture, Security & Benchmark Enhancements

## Executive Summary

This document details the completed security hardening, algorithmic optimizations, and empirical benchmarks for the LLM-TOP protocol core. All updates are fully backward-compatible with v1.0 specifications.

---

## 1. Completed Security & Architectural Hardening

### 1.1 Out-of-Band Host Session Proxy Mode
- **Problem**: Inlining JWT bearer tokens in LLM generation streams (`cap=eyJ...`) risks credential exposure in logs and transcripts, and inflates output payload size.
- **Solution**: Implemented `set_out_of_band_proxy(true)` in `LLMTOPMiddleware`. The LLM outputs clean semantic tool calls (`!read[path=src/main.cpp]`), while the host enforces default-deny authorization against session capability grants bound to `agent_id`.
- **Impact**: Primarily a credential-exposure control. Measured token effect, holding format constant: **73.6% fewer tokens** on authenticated frames, which is simply the cost of the ~200-token JWT no longer being emitted. Any serialization format gains the same benefit from moving capabilities out of band — this is not a property of LLM-TOP's syntax.
- **Withdrawn**: the previously claimed **+25.9% net savings over minified JSON** does not reproduce; it came from a character heuristic in a deleted Python harness. Measured with a real tokenizer, the format-only effect at auth parity is **22.7%**. See [README § Empirical Measurements](README.md#empirical-measurements).

### 1.2 Path Traversal Scope Normalization
- **Problem**: Wildcard scope matching (`read:src/*`) was vulnerable to directory traversal attacks (`read:src/../../../etc/passwd`).
- **Solution**: Added `normalize_path_segment()` to `SimpleJWTValidator::scope_matches()`. All path segments are stripped of leading/trailing slash noise and resolved before wildcard pattern evaluation.
- **Impact**: Completely blocks directory traversal attempts.

### 1.3 Idempotency & Replay Protection Store
- **Problem**: Replayed or duplicated request IDs (`REQID`) could trigger redundant tool side-effects.
- **Solution**: `IdempotencyStore` inside `LLMTOPMiddleware` tracks executed `(agent_id, reqid)` tuples under a mutex and rejects duplicates with `ERR:replay_detected`. Entries carry a TTL; a REQID is recorded only **after** authorization succeeds, so a rejected request does not burn its own ID.
- **Impact**: Blocks replay within the retention window. **LRU eviction was removed deliberately**: evicting the oldest entry to make room lets an attacker flood the store to age out the record of a request they intend to replay. A saturated store now **fails closed**, which trades availability for correctness — sizing it for peak load is the operator's responsibility.

### 1.4 Cryptographic Verification (HMAC-SHA256)
- **Feature**: `SimpleJWTValidator` binds the JWT header's `alg` to a **registered verifier**, so a token cannot select a different or weaker verification path than the one the host installed. Unregistered algorithms — including `none` — are refused.
- **Scope**: **HMAC-SHA256 is the only algorithm shipped.** Earlier revisions of this document claimed Ed25519/EdDSA support via `Algorithm::Ed25519` and `set_public_key()`. That was never a working implementation and has been removed. A host needing asymmetric verification calls `register_verifier("EdDSA", ...)` with a verifier backed by its own audited crypto library; this project will not hand-roll curve arithmetic inside the trust boundary.

---

## 2. Completed Performance & Algorithmic Optimizations

### 2.1 BPE Tokenizer Merge: $O(n \log n)$ and Allocation-Free
- **Problem**: the original merge scan in `Cl100kTokenizer::bpe()` was $O(n^2)$ over byte vectors. The heap rewrite fixed the complexity but still built a temporary `std::string` for every candidate-pair lookup and appended to a per-node string on every merge.
- **Solution**: a min-heap over doubly-linked nodes, where each node is a `(start, len)` range rather than a string. Merges only ever join adjacent nodes, so ranges stay contiguous and a candidate pair is a `std::string_view` over the original piece. Lookups use C++20 heterogeneous hashing (`is_transparent`), so probing allocates nothing; node and heap scratch buffers are reused across pre-tokens.
- **Impact**: **2.6x faster** — 5.59 MB/s to 14.41 MB/s on a 57.6 KB protocol payload (206.2 ms to 79.9 ms over 20 iterations, MSVC `/O2`). Token output is byte-identical, which `test_tokenizer.cpp` enforces by comparing the fast merge against an independent naive reference on every corpus payload.

### 2.1b SHA-256 Block Absorption
- **Problem**: `SHA256::update()` copied input a byte at a time into the block buffer, paying a bounds check and a branch per byte. Every frame is hashed for `CHK`.
- **Solution**: top up any partial block, then transform full blocks directly out of the caller's buffer with no copy at all, retaining only the trailing remainder.

### 2.2 Allocation-Free Scope Matching & JSON Escaping
- **JSON Escaping**: Replaced `std::ostringstream` in `escape_json()` (`json_utils.hpp`) with a directly reserved string buffer.
- **Scope Matching**: `scope_matches()` is now genuinely allocation-free. It walks both scopes as `string_view`s via a cursor instead of building `std::vector<string_view>`, and path normalization writes segment views into a fixed stack buffer instead of `normalize_path_segment()`'s vector-of-strings-then-join. This runs for every pointer and every tool call of every request.
- **Note on an earlier overclaim**: this section previously called the result "zero-allocation" while `scope_matches()` still allocated a vector plus two strings per scope segment. The claim is now true; it was not when it was written.
- **Safety**: a path deeper than 64 segments is refused outright rather than truncated, since silently dropping segments inside an authorization decision would let a long path match a short grant.

### 2.3 Loss-Free Binary Header `OP_HR` Serialization
- **Feature**: Updated `encode_header()` in `binary_encoder.hpp` to serialize `OP_HR` when `hr > 0`, making binary header serialization 100% loss-free alongside `decode_header()`.

---

## 3. Live Model Benchmarks

**Withdrawn.** The table formerly here reported end-to-end latency, generation speed, and
speculative-decoding acceptance rates across four NVIDIA NIM endpoints. Those figures describe a
vendor's serving stack, not this protocol. Its "Output Compliance: 100% Validated" column was a
hardcoded string literal in the harness rather than a measurement, and the sample was two requests
per model.

`run_live_eval.ps1` has been rebuilt to measure honestly — real BPE token counts via `llmtop_eval`,
and parse plus schema validation to report *measured* validity — and prints its own sample size.
Results will be republished when that sample size supports a claim.

---

## 4. Tiktoken BPE Tokenizer Benchmark Summary

Measured via `benchmarker_real.cpp` using the vendored `cl100k_base.tiktoken` ranks file across 7 multi-agent workflow scenarios. Sign convention: positive = LLM-TOP used fewer tokens.

**These baselines are the LLM-TOP frame re-encoded**, so they measure the cost of the syntax, not
the saving from switching to it. For the comparison against a format models actually emit — the
OpenAI `tool_calls` envelope, where LLM-TOP is **73.3% cheaper** — see
[README § Empirical Measurements](README.md#empirical-measurements).

| Scenario | LLM-TOP | Verbose JSON | Minimal JSON | Compact JSON | YAML |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Refactor Request** | 93 | 203 (54%) | 119 (21%) | 122 (23%) | 134 (30%) |
| **Multi-file Plan** | 108 | 241 (55%) | 145 (25%) | 148 (27%) | 167 (35%) |
| **Debugging Session** | 91 | 204 (55%) | 118 (22%) | 121 (24%) | 132 (31%) |
| **Long-context Read** | 74 | 160 (53%) | 95 (22%) | 98 (24%) | 106 (30%) |
| **Synthetic Large Message** | 124 | 237 (47%) | 154 (19%) | 157 (21%) | 171 (27%) |
| **Authenticated Code Reader** | 266 | 353 (24%) | 286 (6%) | 289 (7%) | 298 (10%) |
| **Pathfinding Executor** | 266 | 354 (24%) | 286 (6%) | 289 (7%) | 300 (11%) |

---

## 5. Security & Test Coverage Matrix

- [x] JWT structure validation (header.payload.signature)
- [x] Expiration checking (Unix epoch)
- [x] Scope-based access control with wildcard normalization
- [x] Path traversal blocking (`src/../../../etc/passwd`)
- [x] Idempotency & Replay attack blocking (`IdempotencyStore`, fail-closed at capacity)
- [x] HMAC-SHA256 signature verification, bound to the JWT `alg` via a verifier registry
- [x] Out-of-Band Host Session Proxy Mode
- [x] 3,211 randomized mutation fuzzing iterations across parser, middleware, JWT decode, and
      binary decoder (0 segfaults, 0 unhandled exceptions), asserting output invariants
- [x] 349 runtime checks across 9 suites, passing in Debug **and** Release (assertions survive `NDEBUG`)
