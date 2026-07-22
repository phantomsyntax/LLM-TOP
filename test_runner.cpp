#include <iostream>
#include <string>
#include <vector>
#include "test_harness.hpp"

#include "parser_v2.hpp"

// (Previous tests skipped for brevity, keeping only a few and adding quoted strings)

void test_quoted_strings() {
    std::string payload = 
        "VER:LLM-TOPv1 CHK:sha256:abcd AGT:agent-1 UID:anon TIM:time REQID:req FALLBACK:json HR:0\n"
        "[RSH] ctx:\"Hello [world]\" act:refactor\n"
        "!run[script=\"build [release] env=prod\";target=main.cpp]\n";
    
    LLMTOPParser parser(LLMTOPParser::Mode::STRICT);
    AST ast = parser.parse(payload);
    
    CHECK_EQ(ast.statements.size(), 1);
    
    // Check KV pairs
    CHECK_EQ(ast.statements[0].kvpairs["ctx"], "Hello [world]"); // Quotes stripped, spaces and brackets preserved!
    CHECK_EQ(ast.statements[0].kvpairs["act"], "refactor");

    // Check Tool Calls
    CHECK_EQ(ast.statements[0].tool_calls.size(), 1);
    auto tool = ast.statements[0].tool_calls[0];
    CHECK_EQ(tool.name, "run");
    CHECK_EQ(tool.args["script"], "build [release] env=prod");
    CHECK_EQ(tool.args["target"], "main.cpp");

    std::cout << "[PASS] test_quoted_strings (Lexer works!)\n";
}

void test_self_healing() {
    // Tolerant mode parsing of malformed payloads
    LLMTOPParser parser(LLMTOPParser::Mode::TOLERANT);

    // 1. Test role bracket self-healing
    {
        std::string payload = 
            "VER:LLM-TOPv1 CHK:sha256:abcd AGT:agent-1 UID:anon TIM:time REQID:req FALLBACK:json HR:0\n"
            "[CODER tgt:src/main.cpp act:refactor\n"; // Missing closing bracket
        
        AST ast = parser.parse(payload);
        CHECK_EQ(ast.healed_draft.size(), 1);
        CHECK_EQ(ast.statements.size(), 0);
        CHECK_EQ(ast.healed_draft[0].role, "CODER");
        CHECK_EQ(ast.healed_draft[0].kvpairs["tgt"], "src/main.cpp");
        CHECK_EQ(ast.healed_draft[0].kvpairs["act"], "refactor");
        CHECK_CONTAINS(ast.diagnostic, "Self-healed unclosed role bracket");
    }

    // 2. Test unclosed quote recovery
    {
        std::string payload = 
            "VER:LLM-TOPv1 CHK:sha256:abcd AGT:agent-1 UID:anon TIM:time REQID:req FALLBACK:json HR:0\n"
            "[CODER] ctx:\"unclosed string act:refactor\n"; // Mismatched quotes
        
        AST ast = parser.parse(payload);
        CHECK_EQ(ast.healed_draft.size(), 1);
        CHECK_EQ(ast.statements.size(), 0);
        // Quotes closed automatically, entire rest of line is treated as ctx value
        CHECK_EQ(ast.healed_draft[0].kvpairs["ctx"], "unclosed string act:refactor");
        CHECK_CONTAINS(ast.diagnostic, "Self-healed unclosed quote");
    }

    // 3. Test non-numeric HR header coercion
    {
        std::string payload = 
            "VER:LLM-TOPv1 CHK:sha256:abcd AGT:agent-1 UID:anon TIM:time REQID:req FALLBACK:json HR:invalid_value\n"
            "[CODER] tgt:src/main.cpp act:refactor\n";
        
        AST ast = parser.parse(payload);
        CHECK_EQ(ast.statements.size(), 1);
        CHECK_EQ(ast.healed_draft.size(), 0);
        CHECK_EQ(ast.header.hr, 0); // Coerced to 0
        CHECK_CONTAINS(ast.diagnostic, "Invalid HR value");
    }

    std::cout << "[PASS] test_self_healing (Tolerant self-healing rules verified!)\n";
}

void test_duplicate_keys() {
    // STRICT mode duplicate keys should throw
    {
        std::string payload = 
            "VER:LLM-TOPv1 CHK:sha256:abcd AGT:agent-1 UID:anon TIM:time REQID:req FALLBACK:json HR:0\n"
            "[CODER] tgt:src/main.cpp tgt:src/main_v2.cpp act:refactor\n";
        
        LLMTOPParser parser(LLMTOPParser::Mode::STRICT);
        bool caught = false;
        try {
            parser.parse(payload);
        } catch (const std::runtime_error& e) {
            if (std::string(e.what()).find("Duplicate key") != std::string::npos) {
                caught = true;
            }
        }
        CHECK(caught);
    }

    // TOLERANT mode duplicate keys should take the last and place in healed_draft
    {
        std::string payload = 
            "VER:LLM-TOPv1 CHK:sha256:abcd AGT:agent-1 UID:anon TIM:time REQID:req FALLBACK:json HR:0\n"
            "[CODER] tgt:src/main.cpp tgt:src/main_v2.cpp act:refactor\n";
        
        LLMTOPParser parser(LLMTOPParser::Mode::TOLERANT);
        AST ast = parser.parse(payload);
        
        CHECK_EQ(ast.healed_draft.size(), 1);
        CHECK_EQ(ast.statements.size(), 0);
        CHECK_EQ(ast.healed_draft[0].kvpairs["tgt"], "src/main_v2.cpp"); // Last wins!
        CHECK_CONTAINS(ast.diagnostic, "Duplicate key detected");
    }
    std::cout << "[PASS] test_duplicate_keys\n";
}

void test_tool_name_trimming() {
    std::string payload = 
        "VER:LLM-TOPv1 CHK:sha256:abcd AGT:agent-1 UID:anon TIM:time REQID:req FALLBACK:json HR:0\n"
        "[CODER]\n"
        "! read [path=src/main.cpp] > my_method \n"; // Spaces around read and my_method

    LLMTOPParser parser(LLMTOPParser::Mode::STRICT);
    AST ast = parser.parse(payload);
    
    CHECK_EQ(ast.statements.size(), 1);
    CHECK_EQ(ast.statements[0].tool_calls.size(), 1);
    CHECK_EQ(ast.statements[0].tool_calls[0].name, "read");
    CHECK_EQ(ast.statements[0].tool_calls[0].method, "my_method");
    std::cout << "[PASS] test_tool_name_trimming\n";
}

void test_ordered_serialization() {
    std::string payload = 
        "VER:LLM-TOPv1 CHK:sha256:abcd AGT:agent-1 UID:anon TIM:time REQID:req FALLBACK:json HR:0\n"
        "[CODER] tgt:src/main.cpp act:refactor GL:fix_memory_leak TD:close_db_connection\n";

    LLMTOPParser parser(LLMTOPParser::Mode::STRICT);
    AST ast = parser.parse(payload);

    std::string json_str = toJson(ast);
    
    // Key ordering must be exactly preserved: tgt -> act -> GL -> TD
    size_t pos_tgt = json_str.find("\"tgt\"");
    size_t pos_act = json_str.find("\"act\"");
    size_t pos_gl  = json_str.find("\"GL\"");
    size_t pos_td  = json_str.find("\"TD\"");

    CHECK(pos_tgt != std::string::npos);
    CHECK(pos_act != std::string::npos);
    CHECK(pos_gl != std::string::npos);
    CHECK(pos_td != std::string::npos);

    CHECK(pos_tgt < pos_act);
    CHECK(pos_act < pos_gl);
    CHECK(pos_gl < pos_td);

    std::cout << "[PASS] test_ordered_serialization (Sequence order preserved!)\n";
}

// Fix G: toJson must round-trip all header fields, not just version + checksum.
void test_json_header_fidelity() {
    std::string payload =
        "VER:LLM-TOPv1 CHK:sha256:abcd AGT:agent-7 UID:user-9 TIM:2026-07-18 REQID:req-42 FALLBACK:json HR:2\n"
        "[CODER] tgt:src/main.cpp act:refactor\n";
    LLMTOPParser parser(LLMTOPParser::Mode::STRICT);
    AST ast = parser.parse(payload);

    std::string js = toJson(ast);
    CHECK_CONTAINS(js, "\"agent\": \"agent-7\"");
    CHECK_CONTAINS(js, "\"uid\": \"user-9\"");
    CHECK_CONTAINS(js, "\"time\": \"2026-07-18\"");
    CHECK_CONTAINS(js, "\"reqid\": \"req-42\"");
    CHECK_CONTAINS(js, "\"fallback\": \"json\"");
    CHECK_CONTAINS(js, "\"hr\": 2");

    std::cout << "[PASS] test_json_header_fidelity\n";
}

// S6: a self-healed line must quarantine the statement it belongs to, not the
// previous one. The heal flag used to be set before the previous statement was
// flushed, so a clean statement landed in healed_draft (which the middleware
// rejects) while the malformed one landed in statements (which it accepts) --
// exactly inverting the control.
void test_healed_flag_attribution() {
    LLMTOPParser parser(LLMTOPParser::Mode::TOLERANT);
    AST ast = parser.parse(
        "VER:LLM-TOPv1 CHK:sha256:x AGT:a UID:u TIM:t REQID:r\n"
        "[CLEAN] act:ok\n"
        "[BROKEN] ctx:\"unterminated act:evil\n");

    CHECK_EQ(ast.statements.size(), 1u);
    CHECK_EQ(ast.statements[0].role, "CLEAN");
    CHECK_EQ(ast.healed_draft.size(), 1u);
    CHECK_EQ(ast.healed_draft[0].role, "BROKEN");

    // The same must hold when the healed role line is the very first statement.
    AST first = parser.parse(
        "VER:LLM-TOPv1 CHK:sha256:x AGT:a UID:u TIM:t REQID:r\n"
        "[BROKEN] ctx:\"unterminated act:evil\n"
        "[CLEAN] act:ok\n");
    CHECK_EQ(first.statements.size(), 1u);
    CHECK_EQ(first.statements[0].role, "CLEAN");
    CHECK_EQ(first.healed_draft.size(), 1u);
    CHECK_EQ(first.healed_draft[0].role, "BROKEN");

    std::cout << "[PASS] test_healed_flag_attribution\n";
}

int main() {
    std::cout << "Running LLM-TOP Parser Tests v3...\n";
    test_quoted_strings();
    test_self_healing();
    test_duplicate_keys();
    test_tool_name_trimming();
    test_ordered_serialization();
    test_json_header_fidelity();
    test_healed_flag_attribution();
    std::cout << "All tests completed successfully.\n";
    return TEST_SUMMARY("core_tests");
}
