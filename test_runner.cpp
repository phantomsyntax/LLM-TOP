#include <iostream>
#include <string>
#include <vector>
#include <cassert>

#include "parser_v2.hpp"

// (Previous tests skipped for brevity, keeping only a few and adding quoted strings)

void test_quoted_strings() {
    std::string payload = 
        "VER:LLM-TOPv1 CHK:sha256:abcd AGT:agent-1 UID:anon TIM:time REQID:req FALLBACK:json HR:0\n"
        "[RSH] ctx:\"Hello [world]\" act:refactor\n"
        "!run[script=\"build [release] env=prod\";target=main.cpp]\n";
    
    LLMTOPParser parser(LLMTOPParser::Mode::STRICT);
    AST ast = parser.parse(payload);
    
    assert(ast.statements.size() == 1);
    
    // Check KV pairs
    assert(ast.statements[0].kvpairs["ctx"] == "Hello [world]"); // Quotes stripped, spaces and brackets preserved!
    assert(ast.statements[0].kvpairs["act"] == "refactor");

    // Check Tool Calls
    assert(ast.statements[0].tool_calls.size() == 1);
    auto tool = ast.statements[0].tool_calls[0];
    assert(tool.name == "run");
    assert(tool.args["script"] == "build [release] env=prod");
    assert(tool.args["target"] == "main.cpp");

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
        assert(ast.statements.size() == 1);
        assert(ast.statements[0].role == "CODER");
        assert(ast.statements[0].kvpairs["tgt"] == "src/main.cpp");
        assert(ast.statements[0].kvpairs["act"] == "refactor");
        assert(ast.diagnostic.find("Self-healed unclosed role bracket") != std::string::npos);
    }

    // 2. Test unclosed quote recovery
    {
        std::string payload = 
            "VER:LLM-TOPv1 CHK:sha256:abcd AGT:agent-1 UID:anon TIM:time REQID:req FALLBACK:json HR:0\n"
            "[CODER] ctx:\"unclosed string act:refactor\n"; // Mismatched quotes
        
        AST ast = parser.parse(payload);
        assert(ast.statements.size() == 1);
        // Quotes closed automatically, entire rest of line is treated as ctx value
        assert(ast.statements[0].kvpairs["ctx"] == "unclosed string act:refactor");
        assert(ast.diagnostic.find("Self-healed unclosed quote") != std::string::npos);
    }

    // 3. Test non-numeric HR header coercion
    {
        std::string payload = 
            "VER:LLM-TOPv1 CHK:sha256:abcd AGT:agent-1 UID:anon TIM:time REQID:req FALLBACK:json HR:invalid_value\n"
            "[CODER] tgt:src/main.cpp act:refactor\n";
        
        AST ast = parser.parse(payload);
        assert(ast.header.hr == 0); // Coerced to 0
        assert(ast.diagnostic.find("Invalid HR value") != std::string::npos);
    }

    std::cout << "[PASS] test_self_healing (Tolerant self-healing rules verified!)\n";
}

int main() {
    std::cout << "Running LLM-TOP Parser Tests v3...\n";
    test_quoted_strings();
    test_self_healing();
    std::cout << "All tests completed successfully.\n";
    return 0;
}
