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

int main() {
    std::cout << "Running LLM-TOP Parser Tests v3...\n";
    test_quoted_strings();
    std::cout << "All tests completed successfully.\n";
    return 0;
}
