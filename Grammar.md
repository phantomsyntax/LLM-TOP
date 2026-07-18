# LLM-TOP Formal Grammar (EBNF)
Version: v1.0

This document serves as the formal specification for the LLM-TOP parser.

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

<pointer> ::= <pointer_base> ":" "cap=" <jwt> ";" "ttl=" <iso_8601>
<pointer_base> ::= <file_path> [ "#L" <line_range> ] | "@mem/" <digit> { <digit> }

<string_no_reserved> ::= { ASCII character excluding " ", "[", "]", "!", ">", ":", ";", "=" }
<quoted_string> ::= '"' { ASCII character } '"'
<newline> ::= "\n" | "\r\n"
```

## Parsing Rules
1. **Strict Mode**: A parser MUST reject the payload if the header is missing any mandatory fields (VER, CHK, AGT, UID, TIM, REQID).
2. **Tolerant Mode**: A parser MAY attempt to parse remaining statements if a statement fails to parse, but it must flag the payload with `ERR:parse`.
3. **Capabilities**: Pointers without a valid capability token (`cap`) and time-to-live (`ttl`) should be treated as untrusted and optionally discarded or blocked by the execution environment.
