#include <iostream>
#include "test_harness.hpp"
#include "schema_validator.hpp"

int main() {
    std::cout << "Running LLM-TOP Schema Validator Tests...\n\n";

    // Test 1: Valid CODER statement
    {
        std::cout << "[TEST 1] Valid CODER statement\n";
        AST ast;
        ast.header.ver = "LLM-TOPv1";
        ast.header.agt = "test-agent";
        ast.header.reqid = "req-001";

        Statement stmt;
        stmt.role = "CODER";
        stmt.kvpairs["tgt"] = "src/main.cpp:cap=TOKEN;ttl=2026-07-18T10:00:00Z";
        stmt.kvpairs["act"] = "refactor";
        stmt.kvpairs["GL"] = "fix_memory_leak";

        ToolCall tool;
        tool.name = "read";
        tool.args["path"] = "src/main.cpp";
        stmt.tool_calls.push_back(tool);

        ast.statements.push_back(stmt);

        SchemaValidator validator;
        auto result = validator.validate(ast);

        CHECK(result.valid);
        std::cout << "Result: PASS\n\n";
    }

    // Test 2: Missing required field (GL)
    {
        std::cout << "[TEST 2] Missing required GL field\n";
        AST ast;
        ast.header.ver = "LLM-TOPv1";
        ast.header.agt = "test-agent";
        ast.header.reqid = "req-002";

        Statement stmt;
        stmt.role = "CODER";
        stmt.kvpairs["tgt"] = "src/main.cpp";
        stmt.kvpairs["act"] = "refactor";
        // Missing GL field

        ast.statements.push_back(stmt);

        SchemaValidator validator;
        auto result = validator.validate(ast);

        CHECK(!result.valid);
        CHECK(!result.errors.empty());
        std::cout << "Errors detected: " << result.errors.size() << "\n";
        std::cout << "Result: PASS (correctly rejected)\n\n";
    }

    // Test 3: Unknown role (should warn but not fail)
    {
        std::cout << "[TEST 3] Unknown role type\n";
        AST ast;
        ast.header.ver = "LLM-TOPv1";
        ast.header.agt = "test-agent";
        ast.header.reqid = "req-003";

        Statement stmt;
        stmt.role = "CUSTOM_ROLE";  // Not in schema
        stmt.kvpairs["tgt"] = "src/main.cpp";

        ast.statements.push_back(stmt);

        SchemaValidator validator;
        auto result = validator.validate(ast);

        CHECK(result.valid);  // Should still be valid (extensibility)
        CHECK(!result.warnings.empty());
        std::cout << "Warnings detected: " << result.warnings.size() << "\n";
        std::cout << "Result: PASS (allowed with warning)\n\n";
    }

    // Test 4: Pointer field missing capability
    {
        std::cout << "[TEST 4] Pointer field missing capability token\n";
        AST ast;
        ast.header.ver = "LLM-TOPv1";
        ast.header.agt = "test-agent";
        ast.header.reqid = "req-004";

        Statement stmt;
        stmt.role = "CODER";
        stmt.kvpairs["tgt"] = "src/main.cpp";  // Missing cap=...
        stmt.kvpairs["act"] = "refactor";
        stmt.kvpairs["GL"] = "fix_memory_leak";

        ast.statements.push_back(stmt);

        SchemaValidator validator;
        auto result = validator.validate(ast);

        CHECK(!result.warnings.empty());
        std::cout << "Warnings detected: " << result.warnings.size() << "\n";
        std::cout << "Result: PASS (warning issued)\n\n";
    }

    // Test 5: Multiple statements
    {
        std::cout << "[TEST 5] Multiple valid statements\n";
        AST ast;
        ast.header.ver = "LLM-TOPv1";
        ast.header.agt = "test-agent";
        ast.header.reqid = "req-005";

        // Statement 1: CODER
        Statement stmt1;
        stmt1.role = "CODER";
        stmt1.kvpairs["tgt"] = "src/auth.ts:cap=TOKEN;ttl=2026-07-18T10:00:00Z";
        stmt1.kvpairs["act"] = "refactor";
        stmt1.kvpairs["GL"] = "fix_session";
        ast.statements.push_back(stmt1);

        // Statement 2: EXEC
        Statement stmt2;
        stmt2.role = "EXEC";
        stmt2.kvpairs["tgt"] = "tests/auth.test.ts:cap=TOKEN;ttl=2026-07-18T10:00:00Z";
        stmt2.kvpairs["act"] = "execute";
        ast.statements.push_back(stmt2);

        SchemaValidator validator;
        auto result = validator.validate(ast);

        CHECK(result.valid);
        std::cout << "Result: PASS\n\n";
    }

    std::cout << "All schema validator tests passed!\n";
    return TEST_SUMMARY("schema_tests");
}
