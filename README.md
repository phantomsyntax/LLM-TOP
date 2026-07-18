# LLM-TOP (LLM Token-Optimized Protocol)

LLM-TOP is an ultra-dense, token-optimized protocol layer designed specifically for multi-agent LLM orchestration. By stripping away grammatical English and conversational filler in favor of strict, structured key-value markers, LLM-TOP achieves **~55% token reduction** while maintaining perfect semantic fidelity and execution capability.

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

Built out-of-the-box using standard CMake:

```bash
cmake .
cmake --build .
ctest -C Debug -V
```

## Performance & Benchmarks
Based on token counts from 5 real-world multi-agent payload scenarios, LLM-TOP provides substantial token savings compared to alternative formats:
- **vs. Verbose JSON:** **55.0%** median token reduction (range: 44.1% to 57.4%)
- **vs. Compact JSON:** **55.0%** median token reduction (range: 44.1% to 57.4%)
- **vs. Minimal JSON:** **52.8%** median token reduction (range: 42.0% to 55.2%)
- **vs. YAML:** **12.1%** median token reduction (range: -4.0% to 17.0%)

## Why LLM-TOP?
During simulated multi-agent stress tests (Phase 3), we passed highly complex requirements (such as "Implement an A* pathfinding algorithm using a Manhattan distance heuristic") strictly using LLM-TOP shorthands (`GL:AStar_pathfind TD:heur=manhattan`). 

The subagents successfully parsed the intent without any English conversational padding, proving that modern LLMs can bridge massive semantic gaps natively, making LLM-TOP extremely viable for scalable, high-throughput autonomous systems.
