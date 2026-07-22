#include "parser_v2.hpp"
#include "middleware.hpp"
#include "test_support.hpp"
#include "schema_validator.hpp"
#include <iostream>
#include <memory>
#include "test_harness.hpp"

using llmtop_test::fix_chk;
static const std::string TEST_SECRET = llmtop_test::kTestSecret;



void run_scenario_1_auth_reader() {
    std::cout << "\n[INTEGRATION TEST 1] Authenticated Code Reader Scenario...\n";

    auto validator = std::make_shared<SimpleJWTValidator>(TEST_SECRET);
    // Create separate tokens for the resource path and the tool execution
    std::string file_cap = validator->create_token("reader", "src/auth_spec.txt", 9999999999LL);
    std::string tool_cap = validator->create_token("reader", "execute:read:*", 9999999999LL);

    // Payload using relative path to auth_spec.txt
    std::string payload = 
        "VER:LLM-TOPv1 CHK:sha256:1111 AGT:reader UID:anon TIM:2026-07-18 REQID:req1 FALLBACK:json\n"
        "[READER] tgt:src/auth_spec.txt:cap=" + file_cap + " act:analyze GL:summarize_requirements\n"
        "!read[path=src/auth_spec.txt;cap=" + tool_cap + "]\n";

    // 1. Parse payload
    LLMTOPParser parser(LLMTOPParser::Mode::STRICT);
    AST ast = parser.parse(fix_chk(payload));
    CHECK_EQ(ast.statements.size(), 1);
    std::cout << "  - Parsed successfully.\n";

    // 2. Validate Schema
    SchemaValidator schema_val;
    SchemaValidator::ValidationResult schema_res = schema_val.validate(ast);
    CHECK(schema_res.valid);
    std::cout << "  - Schema validation passed.\n";

    // 3. Evaluate Authorization Middleware
    LLMTOPMiddleware middleware(validator, false); // allow_delegation = false
    LLMTOPMiddleware::ExecutionPlan plan = middleware.evaluate(ast);
    CHECK(plan.authorized);
    std::cout << "  - Middleware authorization passed.\n";

    std::cout << "[PASS] Integration Test 1 passed successfully.\n";
}

void run_scenario_2_astar_executor() {
    std::cout << "\n[INTEGRATION TEST 2] Pathfinding Executor Scenario...\n";

    auto validator = std::make_shared<SimpleJWTValidator>(TEST_SECRET);
    // Create separate tokens for the resource path and the tool execution
    std::string file_cap = validator->create_token("coder", "src/astar.cpp", 9999999999LL);
    std::string tool_cap = validator->create_token("coder", "execute:run:*", 9999999999LL);

    std::string payload = 
        "VER:LLM-TOPv1 CHK:sha256:2222 AGT:coder UID:anon TIM:2026-07-18 REQID:req2 FALLBACK:json\n"
        "[EXEC] tgt:src/astar.cpp:cap=" + file_cap + " act:execute GL:run_astar\n"
        "!run[target=src/astar.cpp;cap=" + tool_cap + "]\n";

    // 1. Parse payload
    LLMTOPParser parser(LLMTOPParser::Mode::STRICT);
    AST ast = parser.parse(fix_chk(payload));
    CHECK_EQ(ast.statements.size(), 1);
    std::cout << "  - Parsed successfully.\n";

    // 2. Validate Schema
    SchemaValidator schema_val;
    SchemaValidator::ValidationResult schema_res = schema_val.validate(ast);
    CHECK(schema_res.valid);
    std::cout << "  - Schema validation passed.\n";

    // 3. Evaluate Authorization Middleware
    LLMTOPMiddleware middleware(validator, false);
    LLMTOPMiddleware::ExecutionPlan plan = middleware.evaluate(ast);
    CHECK(plan.authorized);
    std::cout << "  - Middleware authorization passed.\n";
    std::cout << "[PASS] Integration Test 2 passed successfully.\n";
}

int main() {
    std::cout << "Running LLM-TOP Real-World Style Project Integration Tests...\n";
    run_scenario_1_auth_reader();
    run_scenario_2_astar_executor();
    std::cout << "\nAll Integration Tests completed successfully.\n";
    return TEST_SUMMARY("integration_tests");
}
