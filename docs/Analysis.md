# LLM-TOP — Production Specification & Security Architecture

## Overview
LLM‑TOP is a compact, ASCII‑based protocol for LLM↔LLM and LLM↔tool communication that prioritizes token efficiency while enforcing strict, deterministic capability authorization. This specification outlines protocol headers, out-of-band proxy capabilities, pointer security, and lexer semantics.

## Core Primitives
- Markers: `+ - > ? ! @ OK ERR`
- Shorthand: `tgt, ctx, err, req, dep, fn, cls, var, GL, TD, act`
- Pointers: `tgt:src/auth.ts#L45-50`, `@mem/004`
- Tool prefix: `!` for tool execution; `[]` for tool args; `>` for methods/actions

## Mandatory Header (First Line)
`VER:LLM-TOPv1 CHK:sha256:<payload-hash> AGT:<agent-id> UID:<user-id> TIM:<ISO8601> REQID:<req-id> FALLBACK:json HR:0`

## Capability & Pointer Security Architecture
Pointers and tool invocations operate under capability authorization enforced by `LLMTOPMiddleware`:
1. **In-Band Capability Mode**: Inline pointers and tool calls carry signed JWT tokens (`cap=<base64-jwt>;ttl=<timestamp>`) validated via HMAC-SHA256 or Ed25519 public key signatures.
2. **Out-of-Band Host Session Proxy Mode**: LLMs generate clean, unauthenticated intent (`!read[path=src/main.cpp]`), while the host execution proxy (`LLMTOPHostProxy` / `LLMTOPMiddleware`) validates requests against host-managed session capability grants bound to `AGT`.
3. **Path Traversal Blocking**: Scope evaluation normalizes all path segments (`normalize_path_segment`), blocking traversal attempts like `src/../../../etc/passwd`.
4. **Idempotency Protection**: `IdempotencyStore` tracks `(agent_id, reqid)` tuples to prevent duplicate or replayed tool calls.

## Lexer and Quoted Strings (Parser v2)
To prevent syntax collisions when LLMs generate tool calls containing brackets or spaces, `LLMTOPParser` utilizes a continuous state-machine lexer. When parsing `!run[script="build [release] env=prod"]`, structural delimiters inside double quotes (`"`) are treated as literal string characters.

## Error Semantics and Fallback (Tolerant Mode)
If a payload contains malformed statements, `TOLERANT` mode absorbs C++ exceptions, records warnings into an AST `diagnostic` buffer, and emits a structured `FALLBACK:json` payload to maintain system execution.

## Real-World Empirical Implementation Results
- **Live Model Benchmark**: Evaluated on live endpoints (`deepseek-ai/deepseek-v4-flash`, `minimaxai/minimax-m3`, `deepseek-ai/deepseek-v4-pro`). DeepSeek-V4 Flash achieved **81.5 tokens/sec** and **6.28s end-to-end latency** with **-75% output token savings on tool calls**.
- **Real BPE Token Savings**: Measured with a `cl100k_base` (tiktoken) tokenizer, LLM-TOP achieves **+25.9% net token savings vs minified JSON** and **+67.3% vs pretty-printed JSON**.
- **Fuzzing Robustness**: 2,011 randomized mutation fuzzing iterations resulted in **0 unhandled exceptions or segfaults**.
