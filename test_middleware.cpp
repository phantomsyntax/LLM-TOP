#include <iostream>
#include "test_harness.hpp"
#include "parser_v2.hpp"
#include "middleware.hpp"
#include "test_support.hpp"

// Shared secret for all test JWTs
using llmtop_test::fix_chk;
static const std::string TEST_SECRET = llmtop_test::kTestSecret;


void test_middleware_valid_auth() {
    // Create a validator with the test secret
    auto validator = std::make_shared<SimpleJWTValidator>(TEST_SECRET);

    // Create valid tokens with far-future expiration
    std::string kv_token = validator->create_token("planner", "src/main_file", 9999999999LL);
    std::string tool_token = validator->create_token("planner", "execute:read:*", 9999999999LL);

    std::string payload = 
        "VER:LLM-TOPv1 CHK:sha256:abcd AGT:planner UID:anon TIM:2026-07-18 REQID:req1 FALLBACK:json\n"
        "[EXEC] tgt:src/main_file:cap=" + kv_token + "\n"
        "!read[path=readme_md;cap=" + tool_token + "]\n";

    LLMTOPParser parser(LLMTOPParser::Mode::STRICT);
    AST ast = parser.parse(fix_chk(payload));

    LLMTOPMiddleware middleware(validator);
    auto plan = middleware.evaluate(ast);

    if (!plan.authorized) {
        std::cerr << "Error message: " << plan.error_message << std::endl;
    }
    CHECK(plan.authorized);
    CHECK_EQ(plan.approved_actions.size(), 2);
    std::cout << "[PASS] test_middleware_valid_auth\n";
}

void test_middleware_expired_token() {
    auto validator = std::make_shared<SimpleJWTValidator>(TEST_SECRET);

    // Create token with expiration in the past (Unix epoch 1 = 1970)
    std::string expired_token = validator->create_token("planner", "src/main_file", 1LL);

    std::string payload = 
        "VER:LLM-TOPv1 CHK:sha256:abcd AGT:planner UID:anon TIM:2026-07-18 REQID:req2 FALLBACK:json\n"
        "[EXEC] tgt:src/main_file:cap=" + expired_token + "\n";

    LLMTOPParser parser(LLMTOPParser::Mode::STRICT);
    AST ast = parser.parse(fix_chk(payload));

    LLMTOPMiddleware middleware(validator);
    auto plan = middleware.evaluate(ast);

    CHECK(!(plan.authorized));
    CHECK_CONTAINS(plan.error_message, "ERR:cap_invalid_or_expired");
    std::cout << "[PASS] test_middleware_expired_token\n";
}

void test_middleware_invalid_signature() {
    auto validator = std::make_shared<SimpleJWTValidator>(TEST_SECRET);

    // Create a token with a DIFFERENT secret — signature won't match
    SimpleJWTValidator wrong_signer("wrong-secret-key");
    std::string bad_token = wrong_signer.create_token("planner", "execute:read", 9999999999LL);

    std::string payload = 
        "VER:LLM-TOPv1 CHK:sha256:abcd AGT:planner UID:anon TIM:2026-07-18 REQID:req3 FALLBACK:json\n"
        "!read[path=readme_md;cap=" + bad_token + "]\n";

    LLMTOPParser parser(LLMTOPParser::Mode::STRICT);
    AST ast = parser.parse(fix_chk(payload));

    LLMTOPMiddleware middleware(validator);
    auto plan = middleware.evaluate(ast);

    CHECK(!(plan.authorized));
    CHECK_CONTAINS(plan.error_message, "ERR:exec - Unauthorized tool call");
    std::cout << "[PASS] test_middleware_invalid_signature\n";
}

void test_middleware_tampered_payload() {
    auto validator = std::make_shared<SimpleJWTValidator>(TEST_SECRET);

    // Create a valid token, then tamper with the payload section
    std::string valid_token = validator->create_token("planner", "execute:read:*", 9999999999LL);
    
    // Find the first dot and modify a character in the payload segment
    size_t dot1 = valid_token.find('.');
    size_t dot2 = valid_token.find('.', dot1 + 1);
    std::string tampered = valid_token;
    if (dot1 + 1 < dot2) {
        tampered[dot1 + 1] = (tampered[dot1 + 1] == 'A') ? 'B' : 'A';
    }

    std::string payload =
        "VER:LLM-TOPv1 CHK:sha256:abcd AGT:planner UID:anon TIM:2026-07-18 REQID:req4 FALLBACK:json\n"
        "!read[path=readme_md;cap=" + tampered + "]\n";

    LLMTOPParser parser(LLMTOPParser::Mode::STRICT);
    AST ast = parser.parse(fix_chk(payload));

    LLMTOPMiddleware middleware(validator);
    auto plan = middleware.evaluate(ast);

    CHECK(!(plan.authorized));
    std::cout << "[PASS] test_middleware_tampered_payload\n";
}

void test_middleware_no_agent() {
    auto validator = std::make_shared<SimpleJWTValidator>(TEST_SECRET);
    
    AST ast;
    ast.header.ver = "LLM-TOPv1";
    ast.header.reqid = "req5";
    // Missing agt

    LLMTOPMiddleware middleware(validator);
    auto plan = middleware.evaluate(ast);

    CHECK(!(plan.authorized));
    CHECK_CONTAINS(plan.error_message, "ERR:auth_rejected");
    std::cout << "[PASS] test_middleware_no_agent\n";
}

void test_base64url_roundtrip() {
    for (size_t len = 0; len < 100; ++len) {
        std::string original(len, 'a');
        for (size_t i = 0; i < len; ++i) {
            original[i] = static_cast<char>((i * 17 + 5) & 0xFF);
        }
        std::string encoded = SimpleJWTValidator::base64url_encode(original);
        std::string decoded = SimpleJWTValidator::base64url_decode(encoded);
        if (decoded != original) {
            std::cerr << "Base64 URL mismatch at length " << len << "\n";
            std::cerr << "Original (hex): ";
            for (char c : original) std::cerr << std::hex << (static_cast<int>(c) & 0xFF) << " ";
            std::cerr << "\nDecoded (hex): ";
            for (char c : decoded) std::cerr << std::hex << (static_cast<int>(c) & 0xFF) << " ";
            std::cerr << "\n";
        }
        CHECK_EQ(decoded, original);
    }
    std::cout << "[PASS] test_base64url_roundtrip\n";
}

void test_security_hardening() {
    // 1. sub == agent_id check (default-on)
    {
        auto validator = std::make_shared<SimpleJWTValidator>(TEST_SECRET);
        
        // Token for agent "planner"
        std::string cap = validator->create_token("planner", "execute:read:*", 9999999999LL);
        
        std::string payload = 
            "VER:LLM-TOPv1 CHK:sha256:abcd AGT:attacker UID:anon TIM:2026-07-18 REQID:req_sec1 FALLBACK:json\n"
            "!read[path=readme_md;cap=" + cap + "]\n"; // AGT is attacker, token is for planner. Should be rejected!

        LLMTOPParser parser(LLMTOPParser::Mode::STRICT);
        AST ast = parser.parse(fix_chk(payload));

        // Default-on sub == agent_id check
        LLMTOPMiddleware middleware(validator, false); // allow_delegation = false
        auto plan = middleware.evaluate(ast);
        CHECK(!(plan.authorized));
        CHECK_CONTAINS(plan.error_message, "Unauthorized tool call");

        // Opt-out (allow_delegation = true)
        LLMTOPMiddleware middleware_del(validator, true);
        auto plan_del = middleware_del.evaluate(ast);
        CHECK(plan_del.authorized);
        std::cout << "[PASS] test_security_hardening - sub==agent_id & delegation\n";
    }

    // 2. alg enforcement (reject anything != HS256)
    {
        auto validator = std::make_shared<SimpleJWTValidator>(TEST_SECRET);
        
        // Token with header {"alg":"none"}
        std::string header = SimpleJWTValidator::base64url_encode("{\"alg\":\"none\",\"typ\":\"JWT\"}");
        std::string payload_json = "{\"sub\":\"planner\",\"scope\":\"execute:read\",\"exp\":9999999999}";
        std::string payload_b64 = SimpleJWTValidator::base64url_encode(payload_json);
        std::string bad_token = header + "." + payload_b64 + "."; // No signature needed for alg:none
        
        std::string payload = 
            "VER:LLM-TOPv1 CHK:sha256:abcd AGT:planner UID:anon TIM:2026-07-18 REQID:req_sec2 FALLBACK:json\n"
            "!read[path=readme_md;cap=" + bad_token + "]\n";

        LLMTOPParser parser(LLMTOPParser::Mode::STRICT);
        AST ast = parser.parse(fix_chk(payload));

        LLMTOPMiddleware middleware(validator);
        auto plan = middleware.evaluate(ast);
        CHECK(!(plan.authorized));
        std::cout << "[PASS] test_security_hardening - alg enforcement (none rejected)\n";
    }

    // 3. iss and aud claim support
    {
        // Enforce iss and aud in validator config
        auto validator = std::make_shared<SimpleJWTValidator>(TEST_SECRET, false, "trusted_issuer", "my_agent");

        // Token missing iss/aud or with incorrect ones
        std::string bad_token = validator->create_token("planner", "execute:read:*", 9999999999LL, "bad_issuer", "my_agent");
        std::string good_token = validator->create_token("planner", "execute:read:*", 9999999999LL, "trusted_issuer", "my_agent");

        std::string payload_bad = 
            "VER:LLM-TOPv1 CHK:sha256:abcd AGT:planner UID:anon TIM:2026-07-18 REQID:req_sec3 FALLBACK:json\n"
            "!read[path=readme_md;cap=" + bad_token + "]\n";

        std::string payload_good = 
            "VER:LLM-TOPv1 CHK:sha256:abcd AGT:planner UID:anon TIM:2026-07-18 REQID:req_sec4 FALLBACK:json\n"
            "!read[path=readme_md;cap=" + good_token + "]\n";

        LLMTOPParser parser(LLMTOPParser::Mode::STRICT);
        
        AST ast_bad = parser.parse(fix_chk(payload_bad));
        LLMTOPMiddleware middleware(validator);
        auto plan_bad = middleware.evaluate(ast_bad);
        CHECK(!(plan_bad.authorized));

        AST ast_good = parser.parse(fix_chk(payload_good));
        auto plan_good = middleware.evaluate(ast_good);
        CHECK(plan_good.authorized);
        std::cout << "[PASS] test_security_hardening - iss and aud claims\n";
    }

    // 4. Input size limit
    {
        // Parser configured with a tiny limit (10 bytes)
        LLMTOPParser tiny_parser(LLMTOPParser::Mode::STRICT, 10);
        
        std::string payload = "VER:LLM-TOPv1 CHK:sha256:abcd AGT:planner UID:anon TIM:2026-07-18 REQID:req FALLBACK:json HR:0\n";
        
        bool caught = false;
        try {
            tiny_parser.parse(fix_chk(payload));
        } catch (const std::runtime_error& e) {
            std::string msg = e.what();
            if (msg.find("Payload size exceeds") != std::string::npos) {
                caught = true;
            }
        }
        CHECK(caught);
        std::cout << "[PASS] test_security_hardening - input size limit\n";
    }

    // 5. Scope matching per-segment glob split on :
    {
        auto validator = std::make_shared<SimpleJWTValidator>(TEST_SECRET);
        
        // Grants read on any resource: matches execute:read:<anything>
        std::string cap1 = validator->create_token("planner", "execute:read:*", 9999999999LL);
        // Grants read on src/* only: does NOT match the write tool below
        std::string cap2 = validator->create_token("planner", "execute:read:src/*", 9999999999LL);

        std::string payload = 
            "VER:LLM-TOPv1 CHK:sha256:abcd AGT:planner UID:anon TIM:2026-07-18 REQID:req FALLBACK:json\n"
            "!read[path=readme_md;cap=" + cap1 + "]\n"
            "!write[path=readme_md;cap=" + cap2 + "]\n";

        LLMTOPParser parser(LLMTOPParser::Mode::STRICT);
        AST ast = parser.parse(fix_chk(payload));

        LLMTOPMiddleware middleware(validator);
        auto plan = middleware.evaluate(ast);
        CHECK(!(plan.authorized)); // Should fail on write tool
        CHECK_CONTAINS(plan.error_message, "Unauthorized tool call: write");

        // Let's test standard matching
        std::string payload_ok = 
            "VER:LLM-TOPv1 CHK:sha256:abcd AGT:planner UID:anon TIM:2026-07-18 REQID:req FALLBACK:json\n"
            "!read[path=readme_md;cap=" + cap1 + "]\n";
        AST ast_ok = parser.parse(fix_chk(payload_ok));
        auto plan_ok = middleware.evaluate(ast_ok);
        CHECK(plan_ok.authorized);

        std::cout << "[PASS] test_security_hardening - per-segment glob matching\n";
    }
}

// Fix A: the middleware must default-deny. A tool call or a tgt pointer with no
// capability must be rejected; a pure planning statement (no tool, no pointer) passes.
void test_fail_open_default_deny() {
    auto validator = std::make_shared<SimpleJWTValidator>(TEST_SECRET);
    LLMTOPParser parser(LLMTOPParser::Mode::STRICT);

    // (a) Tool call with NO capability -> reject
    {
        AST ast = parser.parse(fix_chk(
            "VER:LLM-TOPv1 CHK:sha256:abcd AGT:planner UID:anon TIM:2026-07-18 REQID:req_fo1 FALLBACK:json\n"
            "!read[path=/etc/secrets]\n"));
        LLMTOPMiddleware middleware(validator);
        auto plan = middleware.evaluate(ast);
        CHECK(!(plan.authorized));
    }

    // (b) tgt pointer with NO capability -> reject
    {
        AST ast = parser.parse(fix_chk(
            "VER:LLM-TOPv1 CHK:sha256:abcd AGT:planner UID:anon TIM:2026-07-18 REQID:req_fo2 FALLBACK:json\n"
            "[EXEC] tgt:src/secret.ts act:read\n"));
        LLMTOPMiddleware middleware(validator);
        auto plan = middleware.evaluate(ast);
        CHECK(!(plan.authorized));
    }

    // (c) Pure planning statement (no tool, no pointer) -> allow
    {
        AST ast = parser.parse(fix_chk(
            "VER:LLM-TOPv1 CHK:sha256:abcd AGT:planner UID:anon TIM:2026-07-18 REQID:req_fo3 FALLBACK:json\n"
            "[PLAN] GL:refactor_auth act:plan\n"));
        LLMTOPMiddleware middleware(validator);
        auto plan = middleware.evaluate(ast);
        CHECK(plan.authorized);
    }

    std::cout << "[PASS] test_fail_open_default_deny\n";
}

// Fix B: the middleware must reject a payload whose body does not match the CHK header.
void test_checksum_integrity() {
    auto validator = std::make_shared<SimpleJWTValidator>(TEST_SECRET);
    LLMTOPParser parser(LLMTOPParser::Mode::STRICT);

    // Correct checksum -> integrity passes (pure-planning statement authorizes)
    {
        AST ast = parser.parse(fix_chk(
            "VER:LLM-TOPv1 CHK:sha256:abcd AGT:planner UID:anon TIM:2026-07-18 REQID:req_ck1 FALLBACK:json\n"
            "[PLAN] GL:do_thing\n"));
        LLMTOPMiddleware middleware(validator);
        auto plan = middleware.evaluate(ast);
        CHECK(plan.authorized);
    }

    // Body tampered after CHK was computed -> integrity fails
    {
        std::string good = fix_chk(
            "VER:LLM-TOPv1 CHK:sha256:abcd AGT:planner UID:anon TIM:2026-07-18 REQID:req_ck2 FALLBACK:json\n"
            "[PLAN] GL:do_thing\n");
        std::string tampered = good;
        size_t p = tampered.find("do_thing");
        tampered.replace(p, 8, "do_EVILx"); // same length, different bytes
        AST ast = parser.parse(tampered);
        LLMTOPMiddleware middleware(validator);
        auto plan = middleware.evaluate(ast);
        CHECK(!(plan.authorized));
        CHECK_CONTAINS(plan.error_message, "ERR:integrity");
    }

    std::cout << "[PASS] test_checksum_integrity\n";
}

// Fix C: an in-band ttl= that has passed must be rejected even if the JWT itself is valid.
void test_ttl_enforcement() {
    auto validator = std::make_shared<SimpleJWTValidator>(TEST_SECRET);
    LLMTOPParser parser(LLMTOPParser::Mode::STRICT);
    std::string tool_cap = validator->create_token("planner", "execute:read:*", 9999999999LL);

    // Expired ttl -> reject
    {
        AST ast = parser.parse(fix_chk(
            "VER:LLM-TOPv1 CHK:sha256:abcd AGT:planner UID:anon TIM:2026-07-18 REQID:req_ttl1 FALLBACK:json\n"
            "!read[path=readme_md;cap=" + tool_cap + ";ttl=2000-01-01T00:00:00Z]\n"));
        LLMTOPMiddleware middleware(validator);
        auto plan = middleware.evaluate(ast);
        CHECK(!(plan.authorized));
    }

    // Future ttl -> allow
    {
        AST ast = parser.parse(fix_chk(
            "VER:LLM-TOPv1 CHK:sha256:abcd AGT:planner UID:anon TIM:2026-07-18 REQID:req_ttl2 FALLBACK:json\n"
            "!read[path=readme_md;cap=" + tool_cap + ";ttl=2999-01-01T00:00:00Z]\n"));
        LLMTOPMiddleware middleware(validator);
        auto plan = middleware.evaluate(ast);
        CHECK(plan.authorized);
    }

    std::cout << "[PASS] test_ttl_enforcement\n";
}

// Fix E: create_token must escape claim values so a crafted sub cannot smuggle a broader scope.
void test_create_token_no_json_injection() {
    auto validator = std::make_shared<SimpleJWTValidator>(TEST_SECRET);
    // A subject that tries to inject its own "scope":"execute:*" into the payload JSON.
    std::string evil_sub = "x\",\"scope\":\"execute:*";
    std::string token = validator->create_token(evil_sub, "execute:read", 9999999999LL);

    auto claim = validator->verify(token);
    CHECK(claim.valid);
    // The legitimately-signed scope must win; the injected "execute:*" must not be honored.
    CHECK_EQ(claim.scope, "execute:read");

    std::cout << "[PASS] test_create_token_no_json_injection\n";
}

// Fix #2: a tool capability must bind to its resource argument, not just the tool name.
// Requested scope is execute:<tool>:<resource>; a token scoped to a specific resource
// must not authorize a different resource.
void test_tool_arg_binding() {
    auto validator = std::make_shared<SimpleJWTValidator>(TEST_SECRET);
    LLMTOPParser parser(LLMTOPParser::Mode::STRICT);

    // Token grants read on src/* only.
    std::string cap = validator->create_token("planner", "execute:read:src/*", 9999999999LL);

    // In-scope resource -> allow
    {
        AST ast = parser.parse(fix_chk(
            "VER:LLM-TOPv1 CHK:sha256:abcd AGT:planner UID:anon TIM:2026-07-18 REQID:req_ab1 FALLBACK:json\n"
            "!read[path=src/auth.ts;cap=" + cap + "]\n"));
        LLMTOPMiddleware middleware(validator);
        auto plan = middleware.evaluate(ast);
        CHECK(plan.authorized);
    }

    // Out-of-scope resource with the SAME token -> reject
    {
        AST ast = parser.parse(fix_chk(
            "VER:LLM-TOPv1 CHK:sha256:abcd AGT:planner UID:anon TIM:2026-07-18 REQID:req_ab2 FALLBACK:json\n"
            "!read[path=/etc/passwd;cap=" + cap + "]\n"));
        LLMTOPMiddleware middleware(validator);
        auto plan = middleware.evaluate(ast);
        CHECK(!(plan.authorized));
    }

    std::cout << "[PASS] test_tool_arg_binding\n";
}

void test_path_traversal_prevention() {
    auto validator = std::make_shared<SimpleJWTValidator>(TEST_SECRET);
    LLMTOPParser parser(LLMTOPParser::Mode::STRICT);

    // Token grants read access to src/* only.
    std::string cap = validator->create_token("planner", "execute:read:src/*", 9999999999LL);

    // Traversal path attempting to break out of src/ -> MUST BE REJECTED
    AST ast = parser.parse(fix_chk(
        "VER:LLM-TOPv1 CHK:sha256:abcd AGT:planner UID:anon TIM:2026-07-18 REQID:req_pt1 FALLBACK:json\n"
        "!read[path=src/../../../etc/passwd;cap=" + cap + "]\n"));

    LLMTOPMiddleware middleware(validator);
    auto plan = middleware.evaluate(ast);

    CHECK(!(plan.authorized));
    std::cout << "[PASS] test_path_traversal_prevention\n";
}

void test_out_of_band_proxy_mode() {
    auto validator = std::make_shared<SimpleJWTValidator>(TEST_SECRET);
    LLMTOPParser parser(LLMTOPParser::Mode::STRICT);

    // Payload WITHOUT inline cap= tokens (Out-of-Band Auth stream)
    std::string payload = 
        "VER:LLM-TOPv1 CHK:sha256:abcd AGT:subagent1 UID:anon TIM:2026-07-18 REQID:req_oob1 FALLBACK:json\n"
        "[TASK] tgt:src/main.cpp act:refactor\n"
        "!read[path=src/main.cpp]\n";

    AST ast = parser.parse(fix_chk(payload));

    // 1. Without proxy mode enabled -> MUST DEFAULT-DENY
    {
        LLMTOPMiddleware middleware(validator);
        auto plan = middleware.evaluate(ast);
        CHECK(!(plan.authorized));
        CHECK_CONTAINS(plan.error_message, "ERR:cap_required");
    }

    // 2. With proxy mode enabled, but agent has NO session grants -> MUST DENY
    {
        LLMTOPMiddleware middleware(validator);
        middleware.set_out_of_band_proxy(true);
        auto plan = middleware.evaluate(ast);
        CHECK(!(plan.authorized));
    }

    // 3. With proxy mode enabled AND session capabilities granted to host proxy -> MUST AUTHORIZE
    {
        LLMTOPMiddleware middleware(validator);
        middleware.set_out_of_band_proxy(true);
        middleware.grant_session_capability("subagent1", "read:src/main.cpp");
        middleware.grant_session_capability("subagent1", "execute:read:src/main.cpp");
        auto plan = middleware.evaluate(ast);
        CHECK(plan.authorized);
        CHECK_EQ(plan.approved_actions.size(), 2);
    }

    // 4. Out-of-scope request via proxy mode -> MUST DENY
    {
        std::string payload_unauth = 
            "VER:LLM-TOPv1 CHK:sha256:abcd AGT:subagent1 UID:anon TIM:2026-07-18 REQID:req_oob2 FALLBACK:json\n"
            "!read[path=/etc/shadow]\n";
        AST ast_unauth = parser.parse(fix_chk(payload_unauth));

        LLMTOPMiddleware middleware(validator);
        middleware.set_out_of_band_proxy(true);
        middleware.grant_session_capability("subagent1", "execute:read:src/*");
        auto plan = middleware.evaluate(ast_unauth);
        CHECK(!(plan.authorized));
    }

    std::cout << "[PASS] test_out_of_band_proxy_mode\n";
}

void test_idempotency_replay_protection() {
    auto validator = std::make_shared<SimpleJWTValidator>(TEST_SECRET);
    LLMTOPParser parser(LLMTOPParser::Mode::STRICT);

    std::string tool_cap = validator->create_token("agent1", "execute:read:*", 9999999999LL);

    std::string payload = 
        "VER:LLM-TOPv1 CHK:sha256:abcd AGT:agent1 UID:anon TIM:2026-07-18 REQID:req_idempotent_1 FALLBACK:json\n"
        "!read[path=src/db.cpp;cap=" + tool_cap + "]\n";

    AST ast = parser.parse(fix_chk(payload));

    LLMTOPMiddleware middleware(validator);
    middleware.set_enforce_idempotency(true);

    // 1st Execution -> MUST SUCCEED
    auto plan1 = middleware.evaluate(ast);
    CHECK(plan1.authorized);

    // 2nd Execution with SAME agent & REQID -> MUST BE REJECTED (REPLAY)
    auto plan2 = middleware.evaluate(ast);
    CHECK(!(plan2.authorized));
    CHECK_CONTAINS(plan2.error_message, "ERR:replay_detected");

    // Different REQID -> MUST SUCCEED
    std::string payload2 = 
        "VER:LLM-TOPv1 CHK:sha256:abcd AGT:agent1 UID:anon TIM:2026-07-18 REQID:req_idempotent_2 FALLBACK:json\n"
        "!read[path=src/db.cpp;cap=" + tool_cap + "]\n";
    AST ast2 = parser.parse(fix_chk(payload2));
    auto plan3 = middleware.evaluate(ast2);
    CHECK(plan3.authorized);

    std::cout << "[PASS] test_idempotency_replay_protection\n";
}

void test_multi_depth_glob_matching() {
    // Single level glob vs multi-depth glob (**)
    CHECK(SimpleJWTValidator::scope_matches("read:src/*", "read:src/main.cpp"));
    CHECK(SimpleJWTValidator::scope_matches("read:src/**", "read:src/sub/deep/main.cpp"));
    CHECK(SimpleJWTValidator::scope_matches("read:**", "read:anything/anywhere.cpp"));
    CHECK(!(SimpleJWTValidator::scope_matches("read:src/*", "read:other/main.cpp")));
    std::cout << "[PASS] test_multi_depth_glob_matching\n";
}

int main() {
    std::cout << "Running LLM-TOP Middleware Tests (Real HMAC-SHA256)...\n";
    test_fail_open_default_deny();
    test_checksum_integrity();
    test_ttl_enforcement();
    test_create_token_no_json_injection();
    test_tool_arg_binding();
    test_path_traversal_prevention();
    test_out_of_band_proxy_mode();
    test_idempotency_replay_protection();
    test_multi_depth_glob_matching();
    test_base64url_roundtrip();
    test_middleware_valid_auth();
    test_middleware_expired_token();
    test_middleware_invalid_signature();
    test_middleware_tampered_payload();
    test_middleware_no_agent();
    test_security_hardening();
    std::cout << "Middleware Tests completed successfully.\n";
    return TEST_SUMMARY("middleware_tests");
}

