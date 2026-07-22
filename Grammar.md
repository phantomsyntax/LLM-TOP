# LLM-TOP Formal Grammar (EBNF)
Version: v1.1

This document serves as the formal specification for the LLM-TOP parser.

**Changes in v1.1**: removed the `@mem/<id>` pointer production and the `ttl=` pointer suffix.
Neither was implemented — `@mem` had no handling anywhere in the parser or middleware, and in-band
`ttl=` was removed from enforcement because it was attacker-controlled data being treated as a
control (a token's real expiry is the signed `exp` claim). A grammar should describe what the
parser does, not what it was once imagined to do.

```ebnf
<message> ::= <header> <newline> { <body> }

<header> ::= "VER:" <ver_string> 
             " CHK:" <hash> 
             " AGT:" <string> 
             " UID:" <string> 
             " TIM:" <iso_8601> 
             " REQID:" <string> 
             [ " FALLBACK:" <fallback_type> ] 
             [ " HR:" <bit> ]

<ver_string> ::= "LLM-TOPv" <digit> { <digit> }
<hash> ::= "sha256:" <hex_string>
<fallback_type> ::= "json" | "none"
<bit> ::= "0" | "1"

<body> ::= <statement> <newline>
<statement> ::= <role_stmt> | <tool_stmt> | <kv_stmt>

<role_stmt> ::= "[" <role_id> "]" [ " " <kv_pairs> ]
<tool_stmt> ::= "!" <tool_name> [ "[" <tool_args> "]" ] [ ">" <method_name> ]
<kv_stmt>   ::= <kv_pairs>

<role_id> ::= <string>
<tool_name> ::= <string>
<method_name> ::= <string>

<kv_pairs> ::= <kv_pair> { " " <kv_pair> }
<kv_pair>  ::= <key> ":" <value>

<tool_args> ::= <tool_arg> { ";" <tool_arg> }
<tool_arg>  ::= <key> "=" <value>

<key>   ::= <string_no_reserved>
<value> ::= <string_no_reserved> | <pointer> | <quoted_string>

<pointer> ::= <pointer_base> [ ":" "cap=" <jwt> ]
<pointer_base> ::= <file_path> [ "#L" <line_range> ]

<string_no_reserved> ::= { ASCII character excluding " ", "[", "]", "!", ">", ":", ";", "=" }
<quoted_string> ::= '"' { ASCII character } '"'
<newline> ::= "\n" | "\r\n"
```

## Parsing Rules
1. **Strict Mode**: A parser MUST reject the payload if the header is missing any mandatory fields (VER, CHK, AGT, UID, TIM, REQID).
2. **Tolerant Mode**: A parser MAY attempt to parse remaining statements if a statement fails to parse, capturing healing warnings in a `diagnostic` buffer.
3. **Capabilities & Scopes**:
   - **In-Band Mode**: Pointers and tool calls carrying `cap=` tokens are verified by HMAC-SHA256. The JWT `alg` header binds to a registered verifier, so a token cannot select an unregistered algorithm; HMAC-SHA256 is the only one shipped. Scope matching supports single-level (`*`) and multi-depth (`**`) glob matching.
   - **Out-of-Band Proxy Mode**: When inline `cap=` tokens are omitted, the thread-safe host proxy (`LLMTOPMiddleware`) verifies actions against host-managed session capability grants bound to `AGT`.
4. **Idempotency**: Thread-safe `IdempotencyStore` records `(AGT, REQID)` tuples to block duplicate/replayed requests. A REQID is recorded only after authorization succeeds, so a rejected request does not consume its own ID.

## Wildcard Semantics

`*` means different things at the two delimiter levels, which is easy to misread when writing a grant:

| Scope | Matches | Does **not** match |
| :--- | :--- | :--- |
| `execute:read:*` | any resource — `*` is one whole colon-segment | — |
| `execute:read:src/*` | `src/main.cpp` | `src/db/pool.cpp` (`*` spans one path segment) |
| `execute:read:src/**` | `src/main.cpp`, `src/db/pool.cpp` | paths outside `src/` |

At the **colon** level a bare `*` is a full wildcard for that segment, so `execute:read:*` grants
every path. At the **slash** level `*` covers exactly one path segment and `**` covers any depth.
Writing `execute:read:*` when you meant `execute:read:src/*` grants far more than intended.

Independently of scope, any resource that escapes the working root (`../../etc/passwd`) is refused
— a `**` grant does not authorize traversal.

## Integrity (`CHK`)

`CHK` is an **unkeyed** SHA-256 over the full frame, including the identity header, with its own
value blanked for the computation. It detects truncation and corruption; it does **not**
authenticate, because anyone modifying a frame can recompute it. Authentication comes from
capabilities.

A model cannot compute SHA-256 over its own output, so an LLM-generated frame never carries a valid
`CHK`. Hosts stamp it at ingest with `stamp_chk()` (`chk.hpp`), or disable verification for that leg
with `set_verify_chk(false)`. The field is only meaningful across a boundary both sides compute over.
