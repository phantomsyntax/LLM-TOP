#include <iostream>
#include <string>
#include <vector>
#include <random>
#include "parser_v2.hpp"
#include "middleware.hpp"
#include "binary_encoder.hpp"
#include "test_support.hpp"

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
                // Note: with MSVC's default /EHsc this cannot catch an access
                // violation -- a genuine memory fault terminates the process and
                // shows up as a ctest failure instead. Absence of crashes here
                // is not evidence of memory safety; that needs a sanitizer.
                local_crashes++;
                std::cerr << "Non-std exception on '" << name << "' iter " << i << std::endl;
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

    // Phase 3: the authorization boundary. The parser was the only surface ever
    // fuzzed, which left the security-critical code paths untested against
    // malformed input. Each case asserts an invariant, not merely the absence
    // of an exception -- a validator that returns garbage without throwing is
    // still broken.
    std::cout << "  Fuzzing middleware + JWT decode... ";
    {
        auto validator = std::make_shared<SimpleJWTValidator>(llmtop_test::kTestSecret);
        const std::string good_cap =
            validator->create_token("agent1", "execute:read:src/*", 9999999999LL);
        const std::string base = stamp_chk(
            "VER:LLM-TOPv1 CHK:sha256:0000 AGT:agent1 UID:u TIM:2026-07-18 REQID:rq1 FALLBACK:json\n"
            "[EXEC] tgt:src/main.cpp:cap=" + good_cap + " act:read\n"
            "!read[path=src/main.cpp;cap=" + good_cap + "]\n");

        int local_crashes = 0;
        for (int i = 0; i < 400; ++i) {
            std::string corrupted = corrupt_payload(base, i + 9000, 1 + (i % 12));
            try {
                LLMTOPParser parser(LLMTOPParser::Mode::TOLERANT);
                AST ast = parser.parse(corrupted);
                LLMTOPMiddleware middleware(validator);
                auto plan = middleware.evaluate(ast);

                // Invariant 1: an authorized plan never carries an error.
                if (plan.authorized && !plan.error_message.empty()) {
                    std::cerr << "INVARIANT: authorized plan has error at iter " << i << "\n";
                    local_crashes++;
                }
                // Invariant 2: a rejected plan approves nothing.
                if (!plan.authorized &&
                    (!plan.approved_tools.empty() || !plan.approved_pointers.empty())) {
                    std::cerr << "INVARIANT: rejected plan has approvals at iter " << i << "\n";
                    local_crashes++;
                }
                // Invariant 3: nothing approved may escape its root.
                for (const auto& t : plan.approved_tools) {
                    if (t.resource.rfind("../", 0) == 0 || t.resource == "..") {
                        std::cerr << "INVARIANT: approved escaping path at iter " << i << "\n";
                        local_crashes++;
                    }
                }
            } catch (const std::exception& e) {
                local_crashes++;
                std::cerr << "Exception in middleware fuzz iter " << i << ": " << e.what() << "\n";
            }
            total_iterations++;
        }

        // Malformed JWTs straight into verify(): never throws, never validates.
        for (int i = 0; i < 400; ++i) {
            std::string token = corrupt_payload(good_cap, i + 4000, 1 + (i % 8));
            try {
                auto claim = validator->verify(token, "execute:read:src/main.cpp");
                // A mutated token must not verify. (A no-op mutation can leave
                // the token intact, so only flag it when it actually changed.)
                if (claim.valid && token != good_cap) {
                    std::cerr << "INVARIANT: mutated token verified at iter " << i << "\n";
                    local_crashes++;
                }
            } catch (const std::exception& e) {
                local_crashes++;
                std::cerr << "Exception in JWT fuzz iter " << i << ": " << e.what() << "\n";
            }
            total_iterations++;
        }
        crash_count += local_crashes;
        std::cout << (local_crashes == 0 ? "OK" : "FAILED") << "\n";
    }

    // Phase 4: the binary decoder. It is expected to throw on malformed input;
    // what must not happen is an out-of-range read or a non-std exception.
    std::cout << "  Fuzzing binary decoder... ";
    {
        BinaryEncoder encoder;
        ordered_map kv;
        kv["tgt"] = "src/main.cpp";
        kv["act"] = "refactor";
        auto header = encoder.encode_header("LLM-TOPv1", "sha256:abcd", "agent", "uid",
                                            "2026-07-18", "rq1", "json", 1);
        auto stmt = encoder.encode_statement("CODER", kv, {});
        std::vector<uint8_t> blob = header;
        blob.insert(blob.end(), stmt.begin(), stmt.end());

        int local_crashes = 0;
        std::mt19937 gen(1234);
        for (int i = 0; i < 400; ++i) {
            std::vector<uint8_t> mutated = blob;
            std::uniform_int_distribution<size_t> pos_dis(0, mutated.size() - 1);
            std::uniform_int_distribution<int> byte_dis(0, 255);
            const int mutations = 1 + (i % 10);
            for (int m = 0; m < mutations; ++m) {
                mutated[pos_dis(gen)] = static_cast<uint8_t>(byte_dis(gen));
            }
            if (i % 5 == 0 && mutated.size() > 8) {
                mutated.resize(mutated.size() - (i % 7) - 1); // truncation
            }
            try {
                size_t pos = 0;
                BinaryEncoder dec;
                dec.decode_header(mutated, pos);
                while (pos < mutated.size()) {
                    size_t before = pos;
                    dec.decode_statement(mutated, pos);
                    if (pos <= before) break;  // guard against a non-advancing decode
                }
            } catch (const std::exception&) {
                // Expected: malformed binary is reported, not tolerated.
            } catch (...) {
                local_crashes++;
                std::cerr << "Non-std exception from binary decoder at iter " << i << "\n";
            }
            total_iterations++;
        }
        crash_count += local_crashes;
        std::cout << (local_crashes == 0 ? "OK" : "FAILED") << "\n";
    }

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
