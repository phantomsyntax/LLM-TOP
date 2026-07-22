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

    // Test 6 (T8): a disallowed tool is an error, not advice. Reporting it as a
    // warning left `valid` true, so the per-role restriction enforced nothing.
    {
        std::cout << "[TEST 6] Tool outside the role's allowed list\n";
        AST ast;
        ast.header.ver = "LLM-TOPv1";
        ast.header.agt = "test-agent";
        ast.header.reqid = "req-006";

        Statement stmt;
        stmt.role = "READ";                       // allows {read} only
        stmt.kvpairs["tgt"] = "src/main.cpp:cap=TOKEN";
        ToolCall tool;
        tool.name = "exec";                       // not allowed for READ
        stmt.tool_calls.push_back(tool);
        ast.statements.push_back(stmt);

        SchemaValidator validator;
        auto result = validator.validate(ast);
        CHECK(!result.valid);
        CHECK(!result.errors.empty());
        std::cout << "Result: PASS (correctly rejected)\n\n";
    }

    // Test 7 (T8): a missing in-band cap= is a warning by default, because
    // out-of-band proxy mode carries no inline tokens, but an error when the
    // deployment declares that it requires them.
    {
        std::cout << "[TEST 7] Missing in-band capability, both modes\n";
        AST ast;
        ast.header.ver = "LLM-TOPv1";
        ast.header.agt = "test-agent";
        ast.header.reqid = "req-007";

        Statement stmt;
        stmt.role = "READ";
        stmt.kvpairs["tgt"] = "src/main.cpp";     // no cap=
        ast.statements.push_back(stmt);

        SchemaValidator lenient;
        auto lenient_result = lenient.validate(ast);
        CHECK(lenient_result.valid);
        CHECK(!lenient_result.warnings.empty());

        SchemaValidator strict;
        strict.set_require_inband_capabilities(true);
        auto strict_result = strict.validate(ast);
        CHECK(!strict_result.valid);
        std::cout << "Result: PASS\n\n";
    }

    // Test 8 (T8): healed statements are validated too, so a host that opts in
    // to accepting them is not accepting unvalidated ones.
    {
        std::cout << "[TEST 8] Healed statements are validated\n";
        AST ast;
        ast.header.ver = "LLM-TOPv1";
        ast.header.agt = "test-agent";
        ast.header.reqid = "req-008";

        Statement healed;
        healed.role = "CODER";
        healed.kvpairs["tgt"] = "src/main.cpp:cap=TOKEN";
        healed.kvpairs["act"] = "refactor";
        // Missing the required GL field.
        ast.healed_draft.push_back(healed);

        SchemaValidator validator;
        auto result = validator.validate(ast);
        CHECK(!result.valid);
        CHECK_CONTAINS(result.errors[0], "HEALED[0]");
        std::cout << "Result: PASS (correctly rejected)\n\n";
    }

    std::cout << "All schema validator tests passed!\n";
    return TEST_SUMMARY("schema_tests");
}
