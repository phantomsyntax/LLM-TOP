#include <iostream>
#include <cassert>
#include "parser_v2.hpp"
#include "middleware.hpp"

// Shared secret for all test JWTs
static const std::string TEST_SECRET = "llm-top-test-secret-key-2026";

void test_middleware_valid_auth() {
    // Create a validator with the test secret
    auto validator = std::make_shared<SimpleJWTValidator>(TEST_SECRET);

    // Create valid tokens with far-future expiration
    std::string kv_token = validator->create_token("planner", "src/main_file", 9999999999LL);
    std::string tool_token = validator->create_token("planner", "execute:read", 9999999999LL);

    std::string payload = 
        "VER:LLM-TOPv1 CHK:sha256:abcd AGT:planner UID:anon TIM:2026-07-18 REQID:req1 FALLBACK:json\n"
        "[EXEC] tgt:src/main_file:cap=" + kv_token + "\n"
        "!read[path=readme_md;cap=" + tool_token + "]\n";

    LLMTOPParser parser(LLMTOPParser::Mode::STRICT);
    AST ast = parser.parse(payload);

    LLMTOPMiddleware middleware(validator);
    auto plan = middleware.evaluate(ast);

    if (!plan.authorized) {
        std::cerr << "Error message: " << plan.error_message << std::endl;
    }
    assert(plan.authorized == true);
    assert(plan.approved_actions.size() == 2);
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
    AST ast = parser.parse(payload);

    LLMTOPMiddleware middleware(validator);
    auto plan = middleware.evaluate(ast);

    assert(plan.authorized == false);
    assert(plan.error_message.find("ERR:cap_invalid_or_expired") != std::string::npos);
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
    AST ast = parser.parse(payload);

    LLMTOPMiddleware middleware(validator);
    auto plan = middleware.evaluate(ast);

    assert(plan.authorized == false);
    assert(plan.error_message.find("ERR:exec - Unauthorized tool call") != std::string::npos);
    std::cout << "[PASS] test_middleware_invalid_signature\n";
}

void test_middleware_tampered_payload() {
    auto validator = std::make_shared<SimpleJWTValidator>(TEST_SECRET);

    // Create a valid token, then tamper with the payload section
    std::string valid_token = validator->create_token("planner", "execute:read", 9999999999LL);
    
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
    AST ast = parser.parse(payload);

    LLMTOPMiddleware middleware(validator);
    auto plan = middleware.evaluate(ast);

    assert(plan.authorized == false);
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

    assert(plan.authorized == false);
    assert(plan.error_message.find("ERR:auth_rejected") != std::string::npos);
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
        assert(decoded == original);
    }
    std::cout << "[PASS] test_base64url_roundtrip\n";
}

void test_security_hardening() {
    // 1. sub == agent_id check (default-on)
    {
        auto validator = std::make_shared<SimpleJWTValidator>(TEST_SECRET);
        
        // Token for agent "planner"
        std::string cap = validator->create_token("planner", "execute:read", 9999999999LL);
        
        std::string payload = 
            "VER:LLM-TOPv1 CHK:sha256:abcd AGT:attacker UID:anon TIM:2026-07-18 REQID:req_sec1 FALLBACK:json\n"
            "!read[path=readme_md;cap=" + cap + "]\n"; // AGT is attacker, token is for planner. Should be rejected!

        LLMTOPParser parser(LLMTOPParser::Mode::STRICT);
        AST ast = parser.parse(payload);

        // Default-on sub == agent_id check
        LLMTOPMiddleware middleware(validator, false); // allow_delegation = false
        auto plan = middleware.evaluate(ast);
        assert(plan.authorized == false);
        assert(plan.error_message.find("Unauthorized tool call") != std::string::npos);

        // Opt-out (allow_delegation = true)
        LLMTOPMiddleware middleware_del(validator, true);
        auto plan_del = middleware_del.evaluate(ast);
        assert(plan_del.authorized == true);
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
        AST ast = parser.parse(payload);

        LLMTOPMiddleware middleware(validator);
        auto plan = middleware.evaluate(ast);
        assert(plan.authorized == false);
        std::cout << "[PASS] test_security_hardening - alg enforcement (none rejected)\n";
    }

    // 3. iss and aud claim support
    {
        // Enforce iss and aud in validator config
        auto validator = std::make_shared<SimpleJWTValidator>(TEST_SECRET, false, "trusted_issuer", "my_agent");

        // Token missing iss/aud or with incorrect ones
        std::string bad_token = validator->create_token("planner", "execute:read", 9999999999LL, "bad_issuer", "my_agent");
        std::string good_token = validator->create_token("planner", "execute:read", 9999999999LL, "trusted_issuer", "my_agent");

        std::string payload_bad = 
            "VER:LLM-TOPv1 CHK:sha256:abcd AGT:planner UID:anon TIM:2026-07-18 REQID:req_sec3 FALLBACK:json\n"
            "!read[path=readme_md;cap=" + bad_token + "]\n";

        std::string payload_good = 
            "VER:LLM-TOPv1 CHK:sha256:abcd AGT:planner UID:anon TIM:2026-07-18 REQID:req_sec4 FALLBACK:json\n"
            "!read[path=readme_md;cap=" + good_token + "]\n";

        LLMTOPParser parser(LLMTOPParser::Mode::STRICT);
        
        AST ast_bad = parser.parse(payload_bad);
        LLMTOPMiddleware middleware(validator);
        auto plan_bad = middleware.evaluate(ast_bad);
        assert(plan_bad.authorized == false);

        AST ast_good = parser.parse(payload_good);
        auto plan_good = middleware.evaluate(ast_good);
        assert(plan_good.authorized == true);
        std::cout << "[PASS] test_security_hardening - iss and aud claims\n";
    }

    // 4. Input size limit
    {
        // Parser configured with a tiny limit (10 bytes)
        LLMTOPParser tiny_parser(LLMTOPParser::Mode::STRICT, 10);
        
        std::string payload = "VER:LLM-TOPv1 CHK:sha256:abcd AGT:planner UID:anon TIM:2026-07-18 REQID:req FALLBACK:json HR:0\n";
        
        bool caught = false;
        try {
            tiny_parser.parse(payload);
        } catch (const std::runtime_error& e) {
            std::string msg = e.what();
            if (msg.find("Payload size exceeds") != std::string::npos) {
                caught = true;
            }
        }
        assert(caught);
        std::cout << "[PASS] test_security_hardening - input size limit\n";
    }

    // 5. Scope matching per-segment glob split on :
    {
        auto validator = std::make_shared<SimpleJWTValidator>(TEST_SECRET);
        
        // Scope with * glob segment: "execute:*"
        std::string cap1 = validator->create_token("planner", "execute:*", 9999999999LL);
        // Scope with prefix segment glob: "execute:src/*"
        std::string cap2 = validator->create_token("planner", "execute:src/*", 9999999999LL);

        std::string payload = 
            "VER:LLM-TOPv1 CHK:sha256:abcd AGT:planner UID:anon TIM:2026-07-18 REQID:req FALLBACK:json\n"
            "!read[path=readme_md;cap=" + cap1 + "]\n"
            "!write[path=readme_md;cap=" + cap2 + "]\n";

        LLMTOPParser parser(LLMTOPParser::Mode::STRICT);
        AST ast = parser.parse(payload);

        LLMTOPMiddleware middleware(validator);
        auto plan = middleware.evaluate(ast);
        assert(plan.authorized == false); // Should fail on write tool
        assert(plan.error_message.find("Unauthorized tool call: write") != std::string::npos);

        // Let's test standard matching
        std::string payload_ok = 
            "VER:LLM-TOPv1 CHK:sha256:abcd AGT:planner UID:anon TIM:2026-07-18 REQID:req FALLBACK:json\n"
            "!read[path=readme_md;cap=" + cap1 + "]\n";
        AST ast_ok = parser.parse(payload_ok);
        auto plan_ok = middleware.evaluate(ast_ok);
        assert(plan_ok.authorized == true);

        std::cout << "[PASS] test_security_hardening - per-segment glob matching\n";
    }
}

int main() {
    std::cout << "Running LLM-TOP Middleware Tests (Real HMAC-SHA256)...\n";
    test_base64url_roundtrip();
    test_middleware_valid_auth();
    test_middleware_expired_token();
    test_middleware_invalid_signature();
    test_middleware_tampered_payload();
    test_middleware_no_agent();
    test_security_hardening();
    std::cout << "Middleware Tests completed successfully.\n";
    return 0;
}

