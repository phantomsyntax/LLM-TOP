# LLM-TOP — Production Specification & Security Architecture

## Overview
LLM‑TOP is a compact, ASCII‑based protocol for LLM↔LLM and LLM↔tool communication that prioritizes token efficiency while enforcing strict, deterministic capability authorization. This specification outlines protocol headers, out-of-band proxy capabilities, pointer security, and lexer semantics.

## Core Primitives
- Markers: `+ - > ? ! @ OK ERR`
- Shorthand: `tgt, ctx, err, req, dep, fn, cls, var, GL, TD, act`
- Pointers: `tgt:src/auth.ts#L45-50` (optionally `:cap=<token>` for in-band authorization)
- Tool prefix: `!` for tool execution; `[]` for tool args; `>` for methods/actions

## Mandatory Header (First Line)
`VER:LLM-TOPv1 CHK:sha256:<payload-hash> AGT:<agent-id> UID:<user-id> TIM:<ISO8601> REQID:<req-id> FALLBACK:json HR:0`

## Capability & Pointer Security Architecture
Pointers and tool invocations operate under capability authorization enforced by `LLMTOPMiddleware`:
1. **In-Band Capability Mode**: Inline pointers and tool calls carry signed JWT tokens (`cap=<base64-jwt>`) verified by HMAC-SHA256. The `alg` header binds to a registered verifier, so a token cannot select an unregistered or weaker path. HMAC-SHA256 is the only algorithm shipped; hosts needing asymmetric verification register their own.
2. **Out-of-Band Host Session Proxy Mode**: LLMs generate clean, unauthenticated intent (`!read[path=src/main.cpp]`), while `LLMTOPMiddleware` validates requests against host-managed session capability grants bound to `AGT`.
3. **Path Confinement**: Scope evaluation normalizes path segments and separately refuses any resource that escapes the working root, so `src/../../../etc/passwd` is rejected regardless of the granted scope.
4. **Idempotency Protection**: `IdempotencyStore` tracks `(agent_id, reqid)` tuples to prevent duplicate or replayed tool calls. IDs are recorded only after authorization succeeds, and a full store fails closed rather than evicting.

## Lexer and Quoted Strings (Parser v2)
To prevent syntax collisions when LLMs generate tool calls containing brackets or spaces, `LLMTOPParser` utilizes a continuous state-machine lexer. When parsing `!run[script="build [release] env=prod"]`, structural delimiters inside double quotes (`"`) are treated as literal string characters.

## Error Semantics and Fallback (Tolerant Mode)
If a payload contains malformed statements, `TOLERANT` mode absorbs C++ exceptions, records warnings into an AST `diagnostic` buffer, and emits a structured `FALLBACK:json` payload to maintain system execution.

## Real-World Empirical Implementation Results

Sign convention: positive = LLM-TOP used fewer tokens. All figures reproduce from
`benchmarker_real.cpp`; see [README § Empirical Measurements](../README.md#empirical-measurements).

- **Output tool-call turns**: **73.3% median reduction** (range 72.5%–81.0%) versus the OpenAI
  `tool_calls` envelope — the format models actually emit.
- **Full context frames**: **53.8%** vs verbose JSON, **23.8%** vs compact JSON, **21.8%** vs
  minimal JSON, **30.2%** vs YAML. These baselines re-encode LLM-TOP's own frame, so they measure
  the cost of the syntax rather than the saving from adopting it.
- **Out-of-band capability handling**: **73.6%** reduction on authenticated frames with the format
  held constant. This is the JWT no longer being emitted, and any format gains it equally.
- **Fuzzing Robustness**: **3,211** randomized mutation iterations across parser, middleware, JWT
  decode, and binary decoder — **0 unhandled exceptions or segfaults**, with output invariants
  asserted rather than only absence of exceptions.

**Withdrawn claims**: the previously published **+25.9% vs minified JSON**, **+67.3% vs
pretty-printed JSON**, **−75% on tool calls** as a protocol property, and the live-model
latency/throughput table. The first two came from a character heuristic in a deleted Python
harness; the third conflated auth mode with serialization format; the fourth measured a vendor's
serving stack over n=2 requests per model.
