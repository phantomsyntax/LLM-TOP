#include <iostream>
#include <string>
#include <vector>
#include <random>
#include "parser_v2.hpp"

// A fuzzer that tests the parser against diverse corrupted and edge-case payloads.
// Verifies that TOLERANT mode never crashes, segfaults, or throws unhandled exceptions.

std::string corrupt_payload(std::string payload, int seed, int num_mutations) {
    std::mt19937 gen(static_cast<unsigned>(seed));
    if (payload.empty()) return payload;

    for (int i = 0; i < num_mutations; ++i) {
        if (payload.empty()) break;
        std::uniform_int_distribution<size_t> pos_dis(0, payload.length() - 1);
        std::uniform_int_distribution<> action_dis(0, 4);
        
        size_t pos = pos_dis(gen);
        int action = action_dis(gen);

        if (action == 0) { // Delete
            payload.erase(pos, 1);
        } else if (action == 1 && pos + 1 < payload.length()) { // Swap
            std::swap(payload[pos], payload[pos + 1]);
        } else if (action == 2) { // Mutate to random printable ASCII
            std::uniform_int_distribution<> char_dis(32, 126);
            payload[pos] = static_cast<char>(char_dis(gen));
        } else if (action == 3) { // Insert random character
            std::uniform_int_distribution<> char_dis(0, 255);
            payload.insert(pos, 1, static_cast<char>(char_dis(gen)));
        } else { // Duplicate a segment
            size_t len = std::min(pos_dis(gen) % 10 + 1, payload.length() - pos);
            payload.insert(pos, payload.substr(pos, len));
        }
    }
    return payload;
}

int main() {
    // Diverse base payloads covering different edge cases
    std::vector<std::pair<std::string, std::string>> test_corpus = {
        {"Standard payload",
         "VER:LLM-TOPv1 CHK:sha256:abcd1234 AGT:ci-agent-3 UID:ci-agent TIM:2026-07-18T08:00:00Z REQID:rq-0001 FALLBACK:json HR:1\n"
         "[RSH] tgt:src/auth.ts#L1-200:cap=eyJhb;ttl=2026-07-18T09:00:00Z act:refactor GL:fix_multi_session TD:add_tests\n"
         "!read[path=$P/src/auth.ts]\n"},

        {"Empty payload", ""},

        {"Header only",
         "VER:LLM-TOPv1 CHK:sha256:test AGT:agent UID:user TIM:2026-07-18 REQID:r1\n"},

        {"Deeply nested quotes",
         "VER:LLM-TOPv1 CHK:sha256:x AGT:a UID:u TIM:t REQID:r\n"
         "[CODER] ctx:\"nested \\\"quotes [inside] \\\\backslash\\\" end\" act:test\n"
         "!run[script=\"build [release] \\\"env=prod\\\" done\";target=\"a;b;c\"]\n"},

        {"Many tool calls",
         "VER:LLM-TOPv1 CHK:sha256:x AGT:a UID:u TIM:t REQID:r\n"
         "[EXEC] tgt:file act:run\n"
         "!read[path=a]\n!write[path=b;content=c]\n!exec[cmd=d]\n"
         "!compile[src=e;out=f]\n!test[suite=g]\n"},

        {"Unicode-like content",
         "VER:LLM-TOPv1 CHK:sha256:x AGT:a UID:u TIM:t REQID:r\n"
         "[CODER] tgt:src/\xC3\xA9tude.cpp act:refactor GL:fix_\xC3\xBC\n"},

        {"Very long value",
         "VER:LLM-TOPv1 CHK:sha256:x AGT:a UID:u TIM:t REQID:r\n"
         "[CODER] tgt:" + std::string(2000, 'A') + " act:test\n"},

        {"Only special characters",
         "!@#$%^&*()[]{}|\\;:'\",.<>?/`~\n"},

        {"Multiple role sections",
         "VER:LLM-TOPv1 CHK:sha256:x AGT:a UID:u TIM:t REQID:r\n"
         "[PLANNER] GL:plan TD:items\n"
         "[CODER] tgt:a act:b GL:c\n"
         "[EXEC] tgt:d act:e\n"
         "[READ] tgt:f\n"},

        {"Malformed header fields",
         "VER CHK AGT UID TIM REQID FALLBACK HR\n"
         "[TEST] act:test\n"},
    };

    std::cout << "Starting LLM-TOP Parser Fuzzing (Enhanced)...\n";
    int total_iterations = 0;
    int crash_count = 0;
    int fallback_count = 0;

    // Phase 1: Fuzz each base payload with varying mutation counts
    for (const auto& [name, base] : test_corpus) {
        std::cout << "  Fuzzing: " << name << "... ";
        int local_crashes = 0;
        int local_fallbacks = 0;

        for (int i = 0; i < 200; ++i) {
            int mutations = 1 + (i % 20); // Vary mutation count: 1 to 20
            std::string corrupted = corrupt_payload(base, i, mutations);
            
            try {
                LLMTOPParser parser(LLMTOPParser::Mode::TOLERANT);
                AST ast = parser.parse(corrupted);
                
                if (!ast.diagnostic.empty()) {
                    local_fallbacks++;
                }
            } catch (const std::exception& e) {
                local_crashes++;
                std::cerr << "C++ Exception on '" << name << "' iter " << i 
                          << ": " << e.what() << std::endl;
            } catch (...) {
                local_crashes++;
                std::cerr << "SEH / Hard Crash on '" << name << "' iter " << i << std::endl;
            }
            total_iterations++;
        }

        crash_count += local_crashes;
        fallback_count += local_fallbacks;
        std::cout << (local_crashes == 0 ? "OK" : "CRASH!") 
                  << " (" << local_fallbacks << " fallbacks)\n";
    }

    // Phase 2: Direct edge case tests (no fuzzing, test specific inputs)
    std::cout << "  Testing edge cases... ";
    std::vector<std::string> edge_cases = {
        "",                                    // Empty
        "\n",                                  // Just newline
        "\n\n\n",                              // Multiple newlines
        "VER:LLM-TOPv1\n",                    // Minimal valid-ish header
        std::string(10000, 'A'),              // Very long single token
        std::string(100, '\0'),               // Null bytes
        "![]\n",                               // Empty tool call
        "!tool_with_no_brackets>method\n",     // Tool without brackets
        "[]\n",                                // Empty role
        "[ROLE\n",                             // Unclosed role bracket
        "!run[key=\"unclosed\n",               // Unclosed quote in tool
    };

    for (const auto& input : edge_cases) {
        try {
            LLMTOPParser parser(LLMTOPParser::Mode::TOLERANT);
            AST ast = parser.parse(input);
            if (!ast.diagnostic.empty()) fallback_count++;
        } catch (const std::exception& e) {
            crash_count++;
            std::cerr << "Edge case crash: " << e.what() << std::endl;
        } catch (...) {
            crash_count++;
            std::cerr << "Edge case SEH crash!" << std::endl;
        }
        total_iterations++;
    }
    std::cout << "OK\n";

    std::cout << "\nFuzzing Completed: " << total_iterations << " iterations.\n";
    std::cout << "Crashes (Unhandled Exceptions): " << crash_count << "\n";
    std::cout << "Graceful Fallbacks (Diagnostics Emitted): " << fallback_count << "\n";

    if (crash_count == 0) {
        std::cout << "[PASS] Fuzzing passed. No segfaults or unhandled exceptions.\n";
        return 0;
    } else {
        std::cout << "[FAIL] Fuzzing detected brittle execution paths.\n";
        return 1;
    }
}
