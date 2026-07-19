# LLM-TOP (LLM Token-Optimized Protocol)

LLM-TOP is an ultra-dense, token-optimized protocol layer designed specifically for multi-agent LLM orchestration. By stripping away grammatical English and conversational filler in favor of strict, structured key-value markers, LLM-TOP trims tokens by **~22–24% versus minified JSON** (and up to **~54% versus pretty-printed JSON**), measured with a real cl100k_base (tiktoken) tokenizer, while preserving structured, executable semantics. See [Performance & Benchmarks](#performance--benchmarks) for the full, baseline-by-baseline breakdown.

## Features
1. **Token Efficiency**: Compresses instructions down to raw semantic markers (`tgt:`, `act:`, `GL:`, `TD:`).
2. **Deterministic Parsing**: A natively-compiled C++ lexer and parser (`LLMTOPParser`) guarantees that complex structures (like nested strings, spaces, and brackets) are isolated and read safely.
3. **Cryptographic Capability Validation**: The middleware parses and cryptographically validates JWT Capability Tokens (`cap`) with Time-To-Live (`ttl`) constraints, outputting structured authorization plans for the hosting environment to enforce.
4. **Structured Recovery Handlers**: When parsing in Tolerant Mode, syntax failures are captured in a `diagnostic` buffer, enabling the host system to construct `FALLBACK:json` payloads and recovery instructions for upstream agents.
5. **Idempotency Tag Support**: Parses idempotency tags, passing metadata to the hosting environment to prevent redundant tool executions.

## Project Architecture
This repository contains the native C++ tooling required to integrate the protocol into an execution pipeline:

- `parser_v2.hpp`: The core parser, featuring a quote-aware lexer state machine.
- `middleware.hpp`: The execution arbiter that cryptographically validates `cap` tokens and enforces TTL limits.
- `CMakeLists.txt`: A cross-platform CMake build orchestrator.
- **Testing & Benchmarking:**
  - `fuzzer.cpp`: A randomized string mutation test proving parser stability.
  - `benchmarker.cpp`: Validates token volume savings.
  - `benchmarker_real.cpp`: Detailed real-world token efficiency measurements.
  - `test_runner.cpp` & `test_middleware.cpp`: Validates syntax boundaries, JWT verification, and scope blocking.
- `llmtop_parse.cpp`: A command-line interface for manual inspection of payloads.

## Building and Testing

Built out-of-the-box using standard CMake. Use an **out-of-source** build directory — it keeps the source tree clean and `build*/` is already git-ignored:

```bash
cmake -B build
cmake --build build --config Debug
ctest --test-dir build -C Debug -V
```

## Performance & Benchmarks
Token counts are measured with a **real cl100k_base (tiktoken) BPE tokenizer** — the vendored ranks file at `data/cl100k_base.tiktoken`, driven by `benchmarker_real.cpp` (`ctest` target `benchmark`) — across 7 multi-agent payload scenarios. Savings depend heavily on which JSON baseline you compare against:

| Baseline | Median token reduction | Range |
|----------|------------------------|-------|
| Pretty-printed / verbose JSON | **53.8%** | 24.6% – 55.4% |
| Compact JSON (`json.dumps`, no spaces) | **23.8%** | 8.0% – 27.0% |
| Minimal JSON (single-character keys) | **21.8%** | 7.0% – 25.5% |
| YAML | **30.2%** | 10.7% – 35.3% |

**Read this honestly:** the headline ~54% only holds against *pretty-printed* JSON, whose indentation and structural punctuation you would never pay for on the wire. Against a **minified JSON** baseline — the realistic comparison — the reduction is **~22–24%**. In the two scenarios that embed a long capability (JWT) token, LLM-TOP repeats that token in both the pointer and the tool call, so its advantage shrinks to ~7% (per-scenario table in `IMPROVEMENTS.md`).

> **Note on earlier figures.** Prior revisions quoted ~53% across every baseline. That came from a hand-rolled token *estimator* that counted each punctuation character as its own token — over-counting exactly the structural punctuation JSON has most of, and inflating the advantage over compact/minimal JSON by roughly 2×. Every number above is re-measured with the real tokenizer.

## Why LLM-TOP?
During simulated multi-agent stress tests (Phase 3), we passed highly complex requirements (such as "Implement an A* pathfinding algorithm using a Manhattan distance heuristic") strictly using LLM-TOP shorthands (`GL:AStar_pathfind TD:heur=manhattan`). 

The subagents successfully parsed the intent without any English conversational padding, proving that modern LLMs can bridge massive semantic gaps natively, making LLM-TOP extremely viable for scalable, high-throughput autonomous systems.
