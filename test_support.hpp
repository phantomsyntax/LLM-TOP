#pragma once
// LLM-TOP-specific helpers shared across test translation units.
// Assertion machinery lives in test_harness.hpp; this header is about payloads.
#include <string>
#include "sha256.hpp"
#include "parser_v2.hpp"   // canonical_for_chk

namespace llmtop_test {

// Shared secret used by every test that mints capability tokens.
inline const std::string kTestSecret = "llm-top-test-secret-key-2026";

// Rewrite the CHK digest of a hand-written payload so it satisfies the
// middleware's integrity check. Uses the same canonicalization the verifier
// does, so what CHK covers is defined in exactly one place.
inline std::string fix_chk(std::string payload) {
    std::string real = SHA256::hash_hex(canonical_for_chk(payload));
    const std::string marker = "CHK:sha256:";
    size_t p = payload.find(marker);
    if (p != std::string::npos) {
        size_t start = p + marker.size();
        size_t end = payload.find_first_of(" \r\n", start);
        if (end == std::string::npos) end = payload.size();
        payload.replace(start, end - start, real);
    }
    return payload;
}

} // namespace llmtop_test
