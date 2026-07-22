# LLM-TOP Audit Remediation — Design

**Date:** 2026-07-22
**Status:** Approved, ready for implementation planning
**Baseline commit:** `0dfaae4`

---

## Context

A full-repo audit on 2026-07-22 found ~30 defects across five categories: security holes in the
capability/JWT boundary, a test suite structurally incapable of failing, published benchmark
figures produced by a method the repo's own README disavows, allocation-heavy hot loops, and
documentation asserting features that do not exist.

Six of the security findings were confirmed by compiling a probe against the project headers and
observing actual behavior, not by reading alone:

| # | Confirmed behavior |
|---|---|
| S1 | A JWT with `alg:"Ed25519"` signed with the HMAC shared secret verifies as valid |
| S2 | `read:src/*` authorizes `read:src/sub/deep/main.cpp`; `read:src*` authorizes `read:src_secrets/key.pem` |
| S3 | A nested `{"realm_access":{"scope":"execute:**"}}` overrides the top-level `scope` claim |
| S4 | Rewriting `AGT` in flight with `CHK` untouched still authorizes |
| S5 | An unauthorized request permanently burns its `REQID`; the legitimate retry is rejected as a replay |
| S6 | A self-healed statement lands in `statements` (accepted) while the clean statement lands in `healed_draft` (rejected) |

Additionally: `ctest -C Release` reports 9/9 passing, and `assert(1==2)` compiled `/DNDEBUG` exits 0
without firing. The suite's green status under Release is therefore vacuous.

## Intent

LLM-TOP is being built as **a real library that other people will clone and put untrusted LLM
output through**. This drives every decision below: the trust boundary must actually hold, and no
published claim may outrun the code.

---

## Decisions

*(Numbered `DEC-n` to avoid collision with the `D-n` documentation findings in Phase 4.)*

### DEC-1. Ed25519 — verifier registry, HMAC-only shipped, all claims deleted

Ed25519 is **not necessary** for this threat model. Asymmetric keys only buy something when the
minter and the verifier occupy different trust domains; in LLM-TOP the host process both issues
session capabilities and enforces them. Out-of-band proxy mode — now the recommended architecture —
carries no JWTs in the stream at all.

The registry is still built, for a different reason: `alg` is currently validated against a
hardcoded string list and then ignored, so verification always runs HMAC. A tighter `if` preserves
that shape and the next algorithm added reintroduces the bug. A registry makes `alg` a lookup key,
so an unregistered algorithm has no reachable code path and "which key verifies this" stops being
separable from "which algorithm is this."

- Build the verifier registry (~40 lines). Ship **only** HMAC-SHA256.
- Delete `enum class Algorithm`, `set_public_key`, `public_key_b64_`, and every Ed25519/EdDSA
  mention across README, Summary.md, IMPROVEMENTS.md, Grammar.md, docs/Analysis.md, docs/Testing.md.
- Document the extension point factually: a host needing asymmetric auth registers its own verifier
  backed by its own crypto library. **No claim that we supply one.**
- Never hand-roll curve arithmetic in the trust boundary.

### DEC-2. Python is deleted entirely

`llmtop_proxy.py` is a second, divergent implementation of the security boundary: it never checks
`CHK` despite a docstring claiming it enforces header integrity, parses tool arguments with a regex
that is not quote-aware, keeps an unbounded replay set, and records REQIDs on success where C++
records them before authorization. The non-quote-aware parse is a genuine parser differential —
`!read[path="a;path=/etc/shadow"]` yields a different `path` on each side.

Delete `llmtop_proxy.py`, `eval_benchmark.py`, `run_live_eval.py`, `run_live_eval_curl.py`,
`run_live_eval_dual.py`, `run_live_eval_fast.py`, `test_nv_api.py`, and `__pycache__/`.

The C++ middleware becomes the single authoritative enforcement point.

### DEC-3. Measurement moves to PowerShell + a C++ helper

The empirical experiment does not need Python. PowerShell handles HTTP natively via
`Invoke-RestMethod`, which also passes the bearer token in-process rather than on a command line —
closing the credential-in-argv exposure of the `curl.exe -H "Authorization: Bearer ..."` harnesses.
Validation and token counting must come from C++ regardless, because that is where the real
tokenizer and the actual enforcement live.

- New `llmtop_eval` binary: validates a payload and emits real cl100k BPE token counts as
  machine-readable output.
- `run_live_eval.ps1` ported to call it, replacing its `.Length` character measurement.
- Every published figure re-derived from a binary in this repo, or struck.

### DEC-4. CHK covers the whole frame and is documented as corruption detection

`CHK` currently digests only the body, leaving `AGT`, `REQID`, `UID`, and `TIM` unprotected. It is
also unkeyed, so it cannot resist a deliberate attacker who simply recomputes it.

- `CHK` digests the **full frame including the identity header**, with the `CHK` field's own value
  zeroed for the computation.
- It stays unkeyed, so it stays free in tokens.
- Documentation stops filing it under the security core. It is integrity against truncation and
  corruption; **authentication comes from capabilities**.

Keying it was rejected: requiring a shared secret to *produce* a payload puts the secret back in the
agent's hands, which is precisely the coupling out-of-band proxy mode exists to eliminate.

### DEC-5. Sequencing — test harness first, then TDD, docs last

Fixing the trust boundary while the verifying tests cannot fail would leave every subsequent claim
resting on assertions that vanish under `NDEBUG`. The harness is a ~30-line header, so ordering it
first costs essentially nothing. Documentation lands last because it must describe final behavior.

---

## Non-goals

- Implementing Ed25519, or any asymmetric algorithm, in-tree.
- Preserving compatibility with existing `CHK` values or existing scope-grant strings. Both change;
  see Breaking Changes.
- Rebuilding the live-model evaluation's *conclusions*. This work rebuilds the measurement
  apparatus; running the experiment and interpreting results is separate.
- Implementing the `@mem` pointer store. It is **removed from Grammar.md entirely**, not marked
  "planned" — same principle as DEC-1, where saying nothing beats saying "not yet."
- Cosmetic `ostringstream` replacements in cold paths (`to_hex`, `get_iso_timestamp`).
- Refactoring unrelated to the findings.

---

## Phase 0 — Make the suite capable of failing

Prerequisite for trusting every later phase.

| ID | Change | Acceptance |
|---|---|---|
| T1 | `test_harness.hpp` providing `CHECK`, `CHECK_EQ`, `CHECK_THROWS` that survive `NDEBUG`, accumulate failures, print a summary, and drive a nonzero exit | A deliberately broken assertion fails the suite under `--config Release`, not just Debug |
| T1 | Convert all 174 assertions across the 7 test files | No `assert(` remains in `test_*.cpp`; `cassert` removed from test TUs |
| T2 | `benchmarker` is **removed from ctest** and kept as a manually-invoked target — it is a benchmark, not a test | No ctest target can pass without evaluating at least one condition |
| T7 | The mock fixtures are **deleted, not relocated**. They are leftovers from the early heuristic-testing stage: one line reads one of them, asserting only that `ifstream` works and that a file contains a string it was written with — no LLM-TOP code is exercised. `astar.cpp` is opened by nothing. The `.gitignore` entry was vestigial anyway, since `LLM_Mock/` sits outside the git root and could never have been tracked | A fresh clone runs the full suite green, and the suite still passes with the `../LLM_Mock` sibling directory renamed away |
| — | CMake sets a default `CMAKE_BUILD_TYPE` and moves to **C++20** (see D-2 in Phase 4); both configs exercised | Documented build commands cover Debug and Release |

**Note:** `test_schema_validator()` and `test_fallback_recovery()` are test bodies living inside
production headers (`schema_validator.hpp`, `fallback_recovery.hpp`). They move to their test TUs.

## Phase 1 — Security core

Each item gets a failing test written before the fix.

| ID | Fix | Acceptance |
|---|---|---|
| S1 | Verifier registry; `alg` binds to a registered verifier | Test: `alg:Ed25519` + valid HMAC signature is **rejected**; unregistered alg has no reachable verify path |
| S2 | `*` matches exactly one segment and never crosses `/`; `**` matches multi-depth; prefix matches anchored | Test: `read:src/*` does **not** match `read:src/sub/deep.cpp`; `read:src*` does **not** match `read:src_secrets/key.pem`; `read:src/**` still matches |
| S3 | Top-level-only claim extraction that understands JSON structure | Test: nested `{"realm_access":{"scope":"execute:**"}}` does not override top-level `scope` |
| S4 | `CHK` over full frame, own field zeroed | Test: rewriting `AGT` with `CHK` untouched is rejected with `ERR:integrity` |
| S5 | Record REQID **after** authorization succeeds; add TTL-based expiry to `IdempotencyStore` | Test: a rejected request does not burn its REQID; entries expire by time, not only by LRU pressure |
| S6 | Move healed-flag attribution after the statement flush | Test: the statement carrying the healed quote lands in `healed_draft`; the clean statement does not |
| S9 | `ExecutionPlan` carries sanitized, normalized arguments instead of prose strings | A host can consume the plan without re-deriving paths; `approved_actions` prose is no longer the only output |
| S10 | Sanitize `reqid` before it enters the generated recovery frame | Test: `REQID:x AGT:admin` cannot inject header fields into the recovery payload |
| S11 | Remove the unsigned in-band `ttl=`; JWT `exp` is the sole expiry authority | `extract_ttl`/`ttl_valid` removed; grammar and docs updated |
| T9 | Synchronize `set_out_of_band_proxy`, `set_enforce_idempotency`, `clear_idempotency_store` | Thread-safety claims are backed by a concurrency test |
| T3 | Add the discriminating glob assertions that would have caught S2 | Covered by S2 acceptance |
| T4 | Replace the mislabeled alg test; it currently passes because the empty signature is rejected earlier | Covered by S1 acceptance |
| T5 | Extend the fuzzer past the parser to middleware, JWT/base64 decode, and the binary decoder; assert output invariants, not just absence of exceptions | Fuzz targets exist for each surface; seeds no longer fixed to a 2,011-input corpus |
| T8 | Schema validator: missing capability and disallowed tool become errors, not warnings; validate `healed_draft`; remove the empty `if` body | A payload with an uncapped pointer fails schema validation |
| P8 | `SHA256::finalize()` resets state or is documented single-shot | Calling twice cannot silently return garbage |

## Phase 2 — Measurement rebuild

| ID | Change | Acceptance |
|---|---|---|
| DEC-2 | Delete all Python listed in Decision DEC-2 | No `.py` files remain; `.gitignore` Python entries removed |
| T6 | Expand tokenizer tests to cover protocol punctuation (`:` `;` `=` `[` `]` runs) and pin the documented ASCII-only limitation | Token counts are trustworthy for the payloads actually being measured |
| DEC-3 | New `llmtop_eval` binary | Validates a payload and emits real BPE counts in machine-readable form |
| DEC-3 | Port `run_live_eval.ps1` to call `llmtop_eval` | No `.Length` character measurement remains |
| F1 | Add out-of-band scenarios to `benchmarker_real.cpp` | 25.9% / 67.3% either reproduce from the real tokenizer or are struck |
| F5 | The hardcoded `"(100% Valid)"` literal dies with `eval_benchmark.py` | — |
| F6 | Present the −75% figure as what it measures: removing the JWT from the stream, not the serialization format | Docs state the comparison's actual variable |
| F7 | **Add** a realistic tool-calling JSON baseline (the shape a real API actually sends) alongside the existing ones, and label the current baselines as encoding LLM-TOP's own AST shape | A reader can compare against the format they would actually use, and baseline provenance is explicit |
| F9 | Binary-encoder compression claims scoped to the host↔host leg | Docs no longer imply it reduces LLM token cost |
| F10 | One sign convention for savings across all tables | — |

## Phase 3 — Performance (scoped)

| ID | Change | Rationale |
|---|---|---|
| P1 | Tokenizer merge loop: nodes as contiguous `(start,len)` ranges over the piece, probed with `string_view` + transparent hash; no per-probe temporary string | Every benchmark number runs through this loop |
| P2 | `SHA256::update` full-block `memcpy` fast path instead of byte-at-a-time | Every payload is hashed for CHK |
| P4 | Remove `scope_matches` allocations (vector + two strings per segment) | It is the auth hot path, and IMPROVEMENTS.md already calls it "zero-allocation" |
| P6 | Fix `ordered_map::operator[]` returning a reference invalidated by later insertion; make `erase` not O(n) over the index; rename `insert` to `insert_or_assign`, which is what it actually does | Latent dangling-reference UB; no method whose name implies the opposite of its behavior |

Explicitly skipped: P3, P5, P7 (cold-path `ostringstream` and string concatenation).

## Phase 4 — Documentation

Every claim must trace to a binary in this repo or be deleted.

| ID | Fix |
|---|---|
| D-1 | `README.md:92` — replace `file:///C:/Development/LLM/LLMTOP/LICENSE` with a relative link |
| D-2 | Resolve C++17 vs C++20 by **moving to C++20** and updating `CMakeLists.txt`, making the docs true rather than the reverse. This is load-bearing, not cosmetic: P1's `string_view` probing of `ranks_` needs C++20 heterogeneous lookup for `unordered_map`. Landing it in Phase 0 unblocks Phase 3 |
| D-3 | `README.md:54` — `fuzzer.exe 2000` takes an argument `main()` does not accept |
| D-4 | Grammar.md → v1.1; `<string_no_reserved>` excludes `:` though every value uses it; `HR ::= 0\|1` vs `std::stoi`; `@mem/NNN` **removed** (per Non-goals); Ed25519 struck |
| D-5 | `tokenizer.hpp:142` — `#include <queue>` inside the class body; duplicated comment block at 139–141 / 153–154 |
| D-6 | Remove dead code: `Algorithm`, `set_public_key`, `public_key_b64_`, `OP_END_MESSAGE`, the near-unreachable `PARTIAL_SUCCESS` path |
| D-7 | `compute_simple_hash` is labeled `djb2:` but seeds 0 instead of 5381; it is non-cryptographic and used for an "audit trail" |
| D-8 | `docs/Testing.md §2` claims `test_middleware.cpp` tests Ed25519 signatures; no such test exists |
| F2 | README line 3 says ~67% over pretty-printed JSON; README line 80's own table says 53.8% |
| F3 | Strike "100% Validated" over n=2 samples, and the asymmetric validation (LLM-TOP by parse+authz, JSON by `json.loads`) |
| F4 | Strike or heavily qualify the latency claims — sequential back-to-back calls to a queue-limited free endpoint |
| F8 | `Agents.md` instructs planners to emit `CHK:sha256:none`, which the middleware rejects 100% of the time; `sample.llmtop`'s CHK is the SHA-512-of-empty-string prefix and it uses undocumented `$P/` expansion |
| — | REVIEW.md finding #1 (path traversal) is now stale — normalization landed. Its other findings remain open and should be reconciled |

---

## Breaking changes

All are acceptable pre-1.0 and must be called out in the README:

1. **`CHK` values change** — the digest now covers the full frame. Every existing payload's checksum
   is invalid.
2. **Scope grants change** — `*` no longer crosses `/`. A grant of `read:src/*` that previously
   authorized `read:src/sub/deep.cpp` no longer does; it must become `read:src/**`.
3. **In-band `ttl=` removed** — payloads carrying it must drop it. JWT `exp` governs expiry.
4. **Python module removed** — any consumer importing `llmtop_proxy` breaks.

---

## Risks

- **Phase 1 touches the middleware's core control flow.** The verifier registry, CHK scope change,
  and idempotency reordering all modify `evaluate()`. Phase 0 must genuinely land first or
  regressions will pass silently.
- **The glob fix will look like a regression.** Existing tests and fixtures encode the loose
  behavior; several will need their grants widened to `**` deliberately, and each such change must
  be a conscious decision rather than a reflex to make the suite green.
- **Re-derived numbers may be worse than published.** The honest figures could undercut the
  project's headline. That is the expected outcome of the exercise, not a failure of it.
- **Phases 0–1 deliver most of the value.** Phase 3 is the most cuttable if scope needs trimming.
