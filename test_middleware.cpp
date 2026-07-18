#include <iostream>
#include <cassert>
#include "parser_v2.hpp"
#include "middleware.hpp"

void test_middleware_valid_auth() {
    std::string payload = 
        "VER:LLM-TOPv1 CHK:sha256:abcd AGT:planner UID:anon TIM:2026-07-18 REQID:req1 FALLBACK:json\n"
        "[EXEC] tgt:src/main_file:cap=hdr.{\"sub\":\"planner\",\"scope\":\"src/main_file\",\"exp\":9999999999}.sig\n"
        "!read[path=readme_md;cap=hdr.{\"sub\":\"planner\",\"scope\":\"execute:read\",\"exp\":9999999999}.sig]\n";

    LLMTOPParser parser(LLMTOPParser::Mode::STRICT);
    AST ast = parser.parse(payload);

    LLMTOPMiddleware middleware;
    auto plan = middleware.evaluate(ast);

    if (!plan.authorized) {
        std::cerr << "Error message: " << plan.error_message << std::endl;
    }
    assert(plan.authorized == true);
    assert(plan.approved_actions.size() == 2);
    std::cout << "[PASS] test_middleware_valid_auth\n";
}

void test_middleware_expired_token() {
    std::string payload = 
        "VER:LLM-TOPv1 CHK:sha256:abcd AGT:planner UID:anon TIM:2026-07-18 REQID:req2 FALLBACK:json\n"
        "[EXEC] tgt:src/main_file:cap=hdr.{\"sub\":\"planner\",\"scope\":\"src/main_file\",\"exp\":1}.sig\n"; // Expired

    LLMTOPParser parser(LLMTOPParser::Mode::STRICT);
    AST ast = parser.parse(payload);

    LLMTOPMiddleware middleware;
    auto plan = middleware.evaluate(ast);

    assert(plan.authorized == false);
    assert(plan.error_message.find("ERR:cap_invalid_or_expired") != std::string::npos);
    std::cout << "[PASS] test_middleware_expired_token\n";
}

void test_middleware_invalid_signature() {
    std::string payload = 
        "VER:LLM-TOPv1 CHK:sha256:abcd AGT:planner UID:anon TIM:2026-07-18 REQID:req3 FALLBACK:json\n"
        "!read[path=readme_md;cap=hdr.{\"sub\":\"planner\",\"scope\":\"execute:read\",\"exp\":9999999999}.]\n";

    LLMTOPParser parser(LLMTOPParser::Mode::STRICT);
    AST ast = parser.parse(payload);

    LLMTOPMiddleware middleware;
    auto plan = middleware.evaluate(ast);

    assert(plan.authorized == false);
    assert(plan.error_message.find("ERR:exec - Unauthorized tool call") != std::string::npos);
    std::cout << "[PASS] test_middleware_invalid_signature\n";
}

int main() {
    std::cout << "Running LLM-TOP Middleware Tests...\n";
    test_middleware_valid_auth();
    test_middleware_expired_token();
    test_middleware_invalid_signature();
    std::cout << "Middleware Tests completed successfully.\n";
    return 0;
}
