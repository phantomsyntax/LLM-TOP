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

int main() {
    std::cout << "Running LLM-TOP Middleware Tests (Real HMAC-SHA256)...\n";
    test_middleware_valid_auth();
    test_middleware_expired_token();
    test_middleware_invalid_signature();
    test_middleware_tampered_payload();
    test_middleware_no_agent();
    std::cout << "Middleware Tests completed successfully.\n";
    return 0;
}
