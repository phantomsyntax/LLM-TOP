#pragma once
// LLM-TOP-specific helpers shared across test translation units.
// Assertion machinery lives in test_harness.hpp; this header is about payloads.
#include <string>
#include "sha256.hpp"

namespace llmtop_test {

// Shared secret used by every test that mints capability tokens.
inline const std::string kTestSecret = "llm-top-test-secret-key-2026";

// Rewrite the CHK digest of a hand-written payload so it satisfies the
// middleware's integrity check. Kept in one place so that changing what CHK
// covers is a single-site edit.
inline std::string fix_chk(std::string payload) {
    size_t nl = payload.find('\n');
    std::string body = (nl == std::string::npos) ? std::string("") : payload.substr(nl + 1);
    std::string real = SHA256::hash_hex(body);
    const std::string marker = "CHK:sha256:";
    size_t p = payload.find(marker);
    if (p != std::string::npos) {
        size_t start = p + marker.size();
        size_t end = payload.find(' ', start);
        if (end == std::string::npos) end = (nl == std::string::npos ? payload.size() : nl);
        payload.replace(start, end - start, real);
    }
    return payload;
}

} // namespace llmtop_test
