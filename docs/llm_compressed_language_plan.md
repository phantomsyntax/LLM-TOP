# LLM-TOP: Core Protocol Plan

*(Status: Fully Implemented natively in C++. See the `LLMTOP/` repository for the core parser, lexer, fuzzer, and validation libraries).*

## Original Proposal
The goal of LLM-TOP is to compress Agent-to-Agent communication by stripping away conversational English. 
Instead of sending:
"Please go into src/main.cpp and refactor the auth logic so it includes a rate limit"

The LLM-TOP protocol replaces it with a highly dense, deterministic ASCII format:
`tgt:src/main.cpp act:refactor GL:auth_logic TD:add_rate_limit`

### The Three Phase Rollout (Completed)
1. **Dictionary/Schema Finalization**: Completed via `Analysis.md` defining strict keys (`tgt`, `act`, `GL`, `TD`, `ctx`) and mandatory headers (`VER`, `CHK`, `AGT`).
2. **System Prompt Engineering**: Completed via `Agents.md` outlining the Planner (Encoder) and Decoder topologies.
3. **Simulated Testing (Phase 3)**: Completed successfully via isolated subagent test loops. The subagents were able to seamlessly ingest extreme shorthands (`TD:heur=manhattan`) and output flawless C++ algorithms, indicating dense shorthand did not cause semantic decay in those runs. (The token-reduction figure itself has since been re-measured with a real cl100k_base tokenizer — **~22–24% vs minified JSON**, up to ~54% vs pretty-printed JSON; see the README. The earlier "~60%" was a punctuation-counting heuristic estimate and is retired.)

This protocol achieves massive latency and cost reductions for LLM architectures communicating at scale.
