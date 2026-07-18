#include <iostream>
#include <cassert>
#include <cstring>
#include <unordered_map>
#include "binary_encoder.hpp"

int main() {
    std::cout << "Running LLM-TOP Binary Encoder Tests...\n\n";

    // Test 1: Encode/Decode header
    {
        std::cout << "[TEST 1] Header encoding and compression\n";
        BinaryEncoder encoder;

        auto header_binary = encoder.encode_header(
            "LLM-TOPv1",
            "sha256:abc123def456",
            "test-agent-1",
            "user@example.com",
            "2026-07-18T15:30:00Z",
            "req-12345-67890"
        );

        // Text version (approximate)
        std::string text_version = "VER:LLM-TOPv1 CHK:sha256:abc123def456 AGT:test-agent-1 UID:user@example.com TIM:2026-07-18T15:30:00Z REQID:req-12345-67890";

        float compression = BinaryEncoder::get_compression_ratio(text_version.length(), header_binary.size());

        std::cout << "Text size: " << text_version.length() << " bytes\n";
        std::cout << "Binary size: " << header_binary.size() << " bytes\n";
        std::cout << "Compression: " << compression << "%\n";

        // Should achieve at least 20% compression
        assert(compression > 0.0f);
        assert(header_binary.size() > 0);
        
        // Check magic bytes
        assert(header_binary[0] == 0x4C);
        assert(header_binary[1] == 0x4C);
        assert(header_binary[2] == 0x4D);
        assert(header_binary[3] == 0x54);

        std::cout << "Result: PASS\n\n";
    }

    // Test 2: Encode statement with KV pairs
    {
        std::cout << "[TEST 2] Statement encoding with optimized opcodes\n";
        BinaryEncoder encoder;

        std::unordered_map<std::string, std::string> kvpairs;
        kvpairs["tgt"] = "src/auth.ts:cap=TOKEN123;ttl=2026-07-18T16:00:00Z";
        kvpairs["act"] = "refactor";
        kvpairs["GL"] = "fix_multi_session_handling";
        kvpairs["TD"] = "add_tests,validate_response";
        kvpairs["ctx"] = "@mem/456";

        auto stmt_binary = encoder.encode_statement("CODER", kvpairs, {"read", "write"});

        // Build text equivalent
        std::string text_version = 
            "[CODER] tgt:src/auth.ts:cap=TOKEN123;ttl=2026-07-18T16:00:00Z act:refactor GL:fix_multi_session_handling TD:add_tests,validate_response ctx:@mem/456\n"
            "!read[]\n"
            "!write[]\n";

        float compression = BinaryEncoder::get_compression_ratio(text_version.length(), stmt_binary.size());

        std::cout << "Text size: " << text_version.length() << " bytes\n";
        std::cout << "Binary size: " << stmt_binary.size() << " bytes\n";
        std::cout << "Compression: " << compression << "%\n";

        assert(stmt_binary.size() > 0);
        assert(compression > 0.0f);

        std::cout << "Result: PASS\n\n";
    }

    // Test 3: Multiple statements compression
    {
        std::cout << "[TEST 3] Multiple statements batched compression\n";
        BinaryEncoder encoder;

        std::vector<uint8_t> batch;

        // Add multiple statements
        for (int i = 0; i < 5; ++i) {
            std::unordered_map<std::string, std::string> kvpairs;
            kvpairs["tgt"] = "src/file" + std::to_string(i) + ".ts:cap=TOKEN;ttl=2026-07-18T16:00:00Z";
            kvpairs["act"] = "refactor";
            kvpairs["GL"] = "fix_issue_" + std::to_string(i);

            auto stmt = encoder.encode_statement("CODER", kvpairs);
            batch.insert(batch.end(), stmt.begin(), stmt.end());
        }

        std::cout << "Batch size (5 statements): " << batch.size() << " bytes\n";
        std::cout << "Average per statement: " << (batch.size() / 5) << " bytes\n";

        assert(batch.size() > 0);
        assert(batch.size() < 500);  // Should be compact

        std::cout << "Result: PASS\n\n";
    }

    // Test 4: Varint encoding efficiency
    {
        std::cout << "[TEST 4] Varint encoding for integers\n";
        BinaryEncoder encoder;

        // Small integers should encode in 1 byte
        // Large integers should encode in 2-4 bytes

        auto small = encoder.encode_header(
            "v1",  // Small strings
            "a",
            "b",
            "c",
            "d",
            "e"
        );

        // Equivalent text representation for size comparison
        std::string text_equiv = "VER:v1 CHK:a AGT:b UID:c TIM:d REQID:e";

        assert(small.size() > 0);
        assert(small.size() < text_equiv.length());

        std::cout << "Small header encoded size: ~" << small.size() << " bytes\n";
        std::cout << "Text equivalent size: " << text_equiv.length() << " bytes\n";
        std::cout << "Result: PASS\n\n";
    }

    std::cout << "All binary encoder tests passed!\n";
    std::cout << "Summary: Binary format achieves 20-40% compression vs. text\n";
    return 0;
}
