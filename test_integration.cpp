#include "parser_v2.hpp"
#include "middleware.hpp"
#include "schema_validator.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <memory>
#include <cassert>

const std::string TEST_SECRET = "llm-top-test-secret-key-2026";

// Rewrite the CHK digest with a correct sha256 over the payload body so the
// integrity-enforcing middleware accepts it.
static std::string fix_chk(std::string payload) {
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

void run_scenario_1_auth_reader() {
    std::cout << "\n[INTEGRATION TEST 1] Authenticated Code Reader Scenario...\n";

    auto validator = std::make_shared<SimpleJWTValidator>(TEST_SECRET);
    // Create separate tokens for the resource path and the tool execution
    std::string file_cap = validator->create_token("reader", "../LLM_Mock/auth_spec.txt", 9999999999LL);
    std::string tool_cap = validator->create_token("reader", "execute:read:*", 9999999999LL);

    // Payload using relative path to auth_spec.txt
    std::string payload = 
        "VER:LLM-TOPv1 CHK:sha256:1111 AGT:reader UID:anon TIM:2026-07-18 REQID:req1 FALLBACK:json\n"
        "[READER] tgt:../LLM_Mock/auth_spec.txt:cap=" + file_cap + " act:analyze GL:summarize_requirements\n"
        "!read[path=../LLM_Mock/auth_spec.txt;cap=" + tool_cap + "]\n";

    // 1. Parse payload
    LLMTOPParser parser(LLMTOPParser::Mode::STRICT);
    AST ast = parser.parse(fix_chk(payload));
    assert(ast.statements.size() == 1);
    std::cout << "  - Parsed successfully.\n";

    // 2. Validate Schema
    SchemaValidator schema_val;
    SchemaValidator::ValidationResult schema_res = schema_val.validate(ast);
    assert(schema_res.valid);
    std::cout << "  - Schema validation passed.\n";

    // 3. Evaluate Authorization Middleware
    LLMTOPMiddleware middleware(validator, false); // allow_delegation = false
    LLMTOPMiddleware::ExecutionPlan plan = middleware.evaluate(ast);
    assert(plan.authorized);
    std::cout << "  - Middleware authorization passed.\n";

    // 4. Simulate Action Execution (Read auth_spec.txt)
    std::ifstream infile("../LLM_Mock/auth_spec.txt");
    assert(infile.good());
    std::stringstream buffer;
    buffer << infile.rdbuf();
    std::string file_content = buffer.str();
    assert(file_content.find("login(string user, string pass)") != std::string::npos);
    std::cout << "  - Dereferenced context content verification: SUCCESS.\n";
    std::cout << "[PASS] Integration Test 1 passed successfully.\n";
}

void run_scenario_2_astar_executor() {
    std::cout << "\n[INTEGRATION TEST 2] Pathfinding Executor Scenario...\n";

    auto validator = std::make_shared<SimpleJWTValidator>(TEST_SECRET);
    // Create separate tokens for the resource path and the tool execution
    std::string file_cap = validator->create_token("coder", "../LLM_Mock/astar.cpp", 9999999999LL);
    std::string tool_cap = validator->create_token("coder", "execute:run:*", 9999999999LL);

    std::string payload = 
        "VER:LLM-TOPv1 CHK:sha256:2222 AGT:coder UID:anon TIM:2026-07-18 REQID:req2 FALLBACK:json\n"
        "[EXEC] tgt:../LLM_Mock/astar.cpp:cap=" + file_cap + " act:execute GL:run_astar\n"
        "!run[target=../LLM_Mock/astar.cpp;cap=" + tool_cap + "]\n";

    // 1. Parse payload
    LLMTOPParser parser(LLMTOPParser::Mode::STRICT);
    AST ast = parser.parse(fix_chk(payload));
    assert(ast.statements.size() == 1);
    std::cout << "  - Parsed successfully.\n";

    // 2. Validate Schema
    SchemaValidator schema_val;
    SchemaValidator::ValidationResult schema_res = schema_val.validate(ast);
    assert(schema_res.valid);
    std::cout << "  - Schema validation passed.\n";

    // 3. Evaluate Authorization Middleware
    LLMTOPMiddleware middleware(validator, false);
    LLMTOPMiddleware::ExecutionPlan plan = middleware.evaluate(ast);
    assert(plan.authorized);
    std::cout << "  - Middleware authorization passed.\n";
    std::cout << "[PASS] Integration Test 2 passed successfully.\n";
}

int main() {
    std::cout << "Running LLM-TOP Real-World Style Project Integration Tests...\n";
    run_scenario_1_auth_reader();
    run_scenario_2_astar_executor();
    std::cout << "\nAll Integration Tests completed successfully.\n";
    return 0;
}
