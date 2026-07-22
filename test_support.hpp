#pragma once
// LLM-TOP-specific helpers shared across test translation units.
// Assertion machinery lives in test_harness.hpp; this header is about payloads.
#include <string>
#include "sha256.hpp"
#include "chk.hpp"   // stamp_chk -- the public producer API the tests now use

namespace llmtop_test {

// Shared secret used by every test that mints capability tokens.
inline const std::string kTestSecret = "llm-top-test-secret-key-2026";

// NOTE: this header used to carry a private fix_chk() that stamped the CHK
// digest onto a payload. That was the *only* implementation of the producer
// side, so every middleware test satisfied the integrity gate through a door no
// consumer of this library had -- which is exactly why it went unnoticed that
// evaluate() could not accept any frame an integrator could build. The stamping
// logic now lives in chk.hpp as stamp_chk(), and the tests call that, so the
// suite exercises the same path a consumer does.

} // namespace llmtop_test
