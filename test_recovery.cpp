#include <iostream>
#include "test_harness.hpp"
#include "fallback_recovery.hpp"

int main() {
    std::cout << "Running LLM-TOP Fallback Recovery Tests...\n\n";

    // Test 1: No errors - clean payload
    {
        std::cout << "[TEST 1] Clean payload (no errors)\n";
        AST ast;
        ast.header.ver = "LLM-TOPv1";
        ast.header.agt = "planner";
        ast.header.reqid = "req-001";

        Statement stmt;
        stmt.role = "CODER";
        stmt.kvpairs["tgt"] = "src/main.cpp";
        stmt.kvpairs["act"] = "refactor";
        ast.statements.push_back(stmt);

        FallbackRecoveryManager recovery;
        auto plan = recovery.analyze_and_recover(ast);

        CHECK_EQ(plan.action, FallbackRecoveryManager::RecoveryAction::NO_ERROR);
        CHECK_EQ(plan.errors_found, 0);
        
        std::cout << "Result: PASS\n\n";
    }

    // Test 2: Partial failure - some statements recovered
    {
        std::cout << "[TEST 2] Partial recovery (some statements parsed)\n";
        AST ast;
        ast.header.ver = "LLM-TOPv1";
        ast.header.agt = "subagent";
        ast.header.reqid = "req-002";
        ast.diagnostic = "Malformed role declaration: [INCOMPLETE";

        Statement stmt;
        stmt.role = "CODER";
        stmt.kvpairs["tgt"] = "src/main.cpp";
        stmt.kvpairs["act"] = "refactor";
        ast.statements.push_back(stmt);

        FallbackRecoveryManager recovery;
        auto plan = recovery.analyze_and_recover(ast, "VER:... [INCOMPLETE");

        CHECK_EQ(plan.action, FallbackRecoveryManager::RecoveryAction::REPARSE_SUGGESTED);
        CHECK(plan.errors_found > 0);
        CHECK(plan.statements_recovered > 0);
        CHECK(!plan.recovery_instruction.empty());
        
        std::cout << "Errors found: " << plan.errors_found << "\n";
        std::cout << "Statements recovered: " << plan.statements_recovered << "\n";
        std::cout << "Recovery instruction generated: YES\n";
        
        // Verify recovery instruction format
        CHECK_CONTAINS(plan.recovery_instruction, "VER:LLM-TOPv1");
        CHECK_CONTAINS(plan.recovery_instruction, "[PLANNER]");
        CHECK_CONTAINS(plan.recovery_instruction, "act:repair");

        std::cout << "Result: PASS\n\n";
    }

    // Test 3: Complete failure - no statements recovered
    {
        std::cout << "[TEST 3] Complete failure (no recovery possible)\n";
        AST ast;
        ast.header.ver = "LLM-TOPv1";
        ast.header.agt = "subagent";
        ast.header.reqid = "req-003";
        ast.diagnostic = "Empty payload";

        FallbackRecoveryManager recovery;
        auto plan = recovery.analyze_and_recover(ast, "");

        CHECK_EQ(plan.action, FallbackRecoveryManager::RecoveryAction::COMPLETE_FAILURE);
        CHECK(plan.errors_found > 0);
        CHECK(!plan.fallback_json.empty());
        
        std::cout << "Fallback JSON generated: YES\n";
        std::cout << "JSON size: " << plan.fallback_json.length() << " bytes\n";

        // Verify fallback JSON structure
        CHECK_CONTAINS(plan.fallback_json, "\"type\": \"FALLBACK\"");
        CHECK_CONTAINS(plan.fallback_json, "\"recovery_status\": \"complete_failure\"");
        CHECK_CONTAINS(plan.fallback_json, "\"support_link\"");

        std::cout << "Result: PASS\n\n";
    }

    // Test 4: Recovery instruction contains helpful hints
    {
        std::cout << "[TEST 4] Recovery instruction with debugging hints\n";
        AST ast;
        ast.header.ver = "LLM-TOPv1";
        ast.header.agt = "subagent";
        ast.header.reqid = "req-004";
        ast.diagnostic = "Malformed KV pair (missing colon): tgt=src/main";

        Statement stmt;
        stmt.role = "CODER";
        stmt.kvpairs["act"] = "refactor";
        ast.statements.push_back(stmt);

        FallbackRecoveryManager recovery;
        auto plan = recovery.analyze_and_recover(ast, "VER:... tgt=src/main");

        CHECK(!plan.recovery_instruction.empty());
        
        // Check for hints
        CHECK_CONTAINS(plan.recovery_instruction, "RECOVERY_HINTS");
        CHECK_CONTAINS(plan.recovery_instruction, "unclosed quotes");
        CHECK_CONTAINS(plan.recovery_instruction, "escape sequences");

        std::cout << "Debugging hints included: YES\n";
        std::cout << "Result: PASS\n\n";
    }

    // Test 5: Fallback JSON includes all recovered statements
    {
        std::cout << "[TEST 5] Fallback JSON preserves recovered statements\n";
        AST ast;
        ast.header.ver = "LLM-TOPv1";
        ast.header.agt = "subagent";
        ast.header.reqid = "req-005";
        ast.diagnostic = "Error in statement 3";

        // Add 2 successfully parsed statements
        for (int i = 0; i < 2; ++i) {
            Statement stmt;
            stmt.role = "CODER";
            stmt.kvpairs["tgt"] = "src/file" + std::to_string(i) + ".cpp";
            stmt.kvpairs["act"] = "refactor";
            ast.statements.push_back(stmt);
        }

        FallbackRecoveryManager recovery;
        auto plan = recovery.analyze_and_recover(ast);

        CHECK_EQ(plan.statements_recovered, 2);

        // Generate fallback JSON
        std::string fallback_json = recovery.generate_fallback_json(ast, plan);
        
        // Verify it includes recovered statements
        CHECK_CONTAINS(fallback_json, "\"recovered_statements\"");
        CHECK_CONTAINS(fallback_json, "src/file0.cpp");
        CHECK_CONTAINS(fallback_json, "src/file1.cpp");

        std::cout << "Recovered statements preserved in JSON: YES\n";
        std::cout << "Result: PASS\n\n";
    }

    // Test 6 (Fix I): error_count reflects the number of diagnostics, not just 0/1
    {
        std::cout << "[TEST 6] error_count reflects number of diagnostics\n";
        AST ast;
        ast.header.ver = "LLM-TOPv1";
        ast.header.agt = "subagent";
        ast.header.reqid = "req-006";
        ast.diagnostic = "err one | err two | err three"; // parser joins with " | "

        Statement stmt;
        stmt.role = "CODER";
        stmt.kvpairs["act"] = "refactor";
        ast.statements.push_back(stmt);

        FallbackRecoveryManager recovery;
        auto plan = recovery.analyze_and_recover(ast, "payload");
        CHECK_EQ(plan.errors_found, 3);
        std::cout << "Result: PASS\n\n";
    }

    // Test 7 (Fix F): fallback JSON must escape attacker-controlled header fields
    {
        std::cout << "[TEST 7] fallback JSON escapes header fields\n";
        AST ast;
        ast.header.ver = "LLM-TOPv1";
        ast.header.agt = "subagent";
        ast.header.reqid = "req\"evil"; // a quote that would break the JSON if unescaped
        ast.diagnostic = "some error";

        FallbackRecoveryManager recovery;
        auto plan = recovery.analyze_and_recover(ast, "");
        std::string js = recovery.generate_fallback_json(ast, plan);
        CHECK_CONTAINS(js, "req\\\"evil"); // escaped, not raw
        std::cout << "Result: PASS\n\n";
    }

    std::cout << "All fallback recovery tests passed!\n";
    std::cout << "Summary: Recovery system successfully handles errors and provides actionable feedback\n";
    return TEST_SUMMARY("recovery_tests");
}
