#include <iostream>
#include <string>
#include <vector>
#include <random>
#include "parser_v2.hpp"

// A simple fuzzer that takes a valid payload and corrupts it.
std::string corrupt_payload(std::string payload, int seed) {
    std::mt19937 gen(seed);
    std::uniform_int_distribution<> dis(0, payload.length() - 1);
    std::uniform_int_distribution<> action_dis(0, 2); // 0: delete, 1: swap, 2: mutate to random char

    int num_mutations = 5; 
    for (int i = 0; i < num_mutations; ++i) {
        if (payload.empty()) break;
        std::uniform_int_distribution<> safe_dis(0, payload.length() - 1);
        int pos = safe_dis(gen);
        int action = action_dis(gen);

        if (action == 0) { // Delete
            payload.erase(pos, 1);
        } else if (action == 1 && pos + 1 < payload.length()) { // Swap
            std::swap(payload[pos], payload[pos + 1]);
        } else { // Mutate
            std::uniform_int_distribution<> char_dis(32, 126); // Printable ASCII
            payload[pos] = static_cast<char>(char_dis(gen));
        }
    }
    return payload;
}

int main() {
    std::string base_payload = 
        "VER:LLM-TOPv1 CHK:sha256:abcd1234 AGT:ci-agent-3 UID:ci-agent TIM:2026-07-18T08:00:00Z REQID:rq-0001 FALLBACK:json HR:1\n"
        "[RSH] tgt:src/auth.ts#L1-200:cap=eyJhb;ttl=2026-07-18T09:00:00Z act:refactor GL:fix_multi_session TD:add_tests\n"
        "!read[path=$P/src/auth.ts]\n";

    std::cout << "Starting LLM-TOP Parser Fuzzing...\n";
    int num_iterations = 1000;
    int crash_count = 0;
    int fallback_count = 0;

    for (int i = 0; i < num_iterations; ++i) {
        std::string corrupted = corrupt_payload(base_payload, i);
        
        try {
            LLMTOPParser parser(LLMTOPParser::Mode::TOLERANT);
            AST ast = parser.parse(corrupted);
            
            if (!ast.diagnostic.empty()) {
                fallback_count++;
            }
        } catch (const std::exception& e) {
            crash_count++;
            std::cerr << "C++ Exception: " << e.what() << std::endl;
        } catch (...) {
            crash_count++;
            std::cerr << "SEH / Hard Crash!" << std::endl;
        }
    }

    std::cout << "Fuzzing Completed: " << num_iterations << " iterations.\n";
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
