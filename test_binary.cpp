#include <iostream>
#include <cassert>
#include <cstring>
#include <vector>
#include "binary_encoder.hpp"
#include "parser_v2.hpp"

// Helper: build a ToolCall with a name (args/method added by the caller).
static ToolCall mk_tool(const std::string& name) {
    ToolCall t;
    t.name = name;
    return t;
}

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

        std::string text_version = "VER:LLM-TOPv1 CHK:sha256:abc123def456 AGT:test-agent-1 UID:user@example.com TIM:2026-07-18T15:30:00Z REQID:req-12345-67890";

        float compression = BinaryEncoder::get_compression_ratio(text_version.length(), header_binary.size());

        std::cout << "Text size: " << text_version.length() << " bytes\n";
        std::cout << "Binary size: " << header_binary.size() << " bytes\n";
        std::cout << "Compression: " << compression << "%\n";

        assert(compression > 0.0f);
        assert(header_binary.size() > 0);
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

        ordered_map kvpairs;
        kvpairs["tgt"] = "src/auth.ts:cap=TOKEN123;ttl=2026-07-18T16:00:00Z";
        kvpairs["act"] = "refactor";
        kvpairs["GL"] = "fix_multi_session_handling";
        kvpairs["TD"] = "add_tests,validate_response";
        kvpairs["ctx"] = "@mem/456";

        auto stmt_binary = encoder.encode_statement("CODER", kvpairs, {mk_tool("read"), mk_tool("write")});

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
        for (int i = 0; i < 5; ++i) {
            ordered_map kvpairs;
            kvpairs["tgt"] = "src/file" + std::to_string(i) + ".ts:cap=TOKEN;ttl=2026-07-18T16:00:00Z";
            kvpairs["act"] = "refactor";
            kvpairs["GL"] = "fix_issue_" + std::to_string(i);

            auto stmt = encoder.encode_statement("CODER", kvpairs);
            batch.insert(batch.end(), stmt.begin(), stmt.end());
        }

        std::cout << "Batch size (5 statements): " << batch.size() << " bytes\n";
        std::cout << "Average per statement: " << (batch.size() / 5) << " bytes\n";

        assert(batch.size() > 0);
        assert(batch.size() < 500);

        std::cout << "Result: PASS\n\n";
    }

    // Test 4: Varint encoding efficiency
    {
        std::cout << "[TEST 4] Varint encoding for integers\n";
        BinaryEncoder encoder;

        auto small = encoder.encode_header("v1", "a", "b", "c", "d", "e");
        std::string text_equiv = "VER:v1 CHK:a AGT:b UID:c TIM:d REQID:e";

        assert(small.size() > 0);
        assert(small.size() < text_equiv.length());

        std::cout << "Small header encoded size: ~" << small.size() << " bytes\n";
        std::cout << "Text equivalent size: " << text_equiv.length() << " bytes\n";
        std::cout << "Result: PASS\n\n";
    }

    // Test 5: Compression of protocol shorthand opcodes (err, req, dep, fn, cls, var)
    {
        std::cout << "[TEST 5] Compression of newly optimized protocol shorthands\n";
        BinaryEncoder encoder;

        ordered_map kvpairs;
        kvpairs["err"] = "missing_dependency";
        kvpairs["req"] = "rq-456";
        kvpairs["dep"] = "libsqlite";
        kvpairs["fn"] = "init_db";
        kvpairs["cls"] = "DatabaseManager";
        kvpairs["var"] = "db_connection";

        auto stmt_binary = encoder.encode_statement("EXEC", kvpairs);

        std::string text_version = "[EXEC] err:missing_dependency req:rq-456 dep:libsqlite fn:init_db cls:DatabaseManager var:db_connection\n";

        float compression = BinaryEncoder::get_compression_ratio(text_version.length(), stmt_binary.size());

        std::cout << "Text size: " << text_version.length() << " bytes\n";
        std::cout << "Binary size: " << stmt_binary.size() << " bytes\n";
        std::cout << "Compression: " << compression << "%\n";

        assert(stmt_binary.size() > 0);
        assert(compression > 15.0f);

        std::cout << "Result: PASS\n\n";
    }

    // Test 6: Full round-trip -- key ORDER, tool ARGS and tool METHOD all preserved.
    {
        std::cout << "[TEST 6] Round-trip preserves key order, tool args and method\n";
        BinaryEncoder encoder;

        // Deliberately non-alphabetical key order to prove insertion order survives.
        ordered_map kv;
        kv["GL"] = "fix_leak";
        kv["tgt"] = "src/auth.ts";
        kv["act"] = "refactor";
        kv["err"] = "missing_dependency";
        kv["custom_key"] = "custom_value"; // exercises the generic (non-opcode) path

        std::vector<ToolCall> tools;
        {
            ToolCall read;
            read.name = "read";
            read.args["path"] = "src/auth.ts";
            tools.push_back(read);
        }
        {
            ToolCall write;
            write.name = "write";
            write.args["path"] = "src/auth.ts";     // note: two args, ordered
            write.args["content"] = "new validation code";
            write.method = "commit";
            tools.push_back(write);
        }

        auto binary = encoder.encode_statement("CODER", kv, tools);

        size_t pos = 0;
        Statement decoded = encoder.decode_statement(binary, pos);

        // Role + values
        assert(decoded.role == "CODER");
        assert(decoded.kvpairs.at("GL") == "fix_leak");
        assert(decoded.kvpairs.at("tgt") == "src/auth.ts");
        assert(decoded.kvpairs.at("act") == "refactor");
        assert(decoded.kvpairs.at("err") == "missing_dependency");
        assert(decoded.kvpairs.at("custom_key") == "custom_value");

        // Key ORDER must match the original insertion order exactly.
        std::vector<std::string> got_order;
        for (const auto& p : decoded.kvpairs) got_order.push_back(p.first);
        std::vector<std::string> want_order = {"GL", "tgt", "act", "err", "custom_key"};
        assert(got_order == want_order);

        // Tool calls: names, args (with their own order), and method.
        assert(decoded.tool_calls.size() == 2);

        assert(decoded.tool_calls[0].name == "read");
        assert(decoded.tool_calls[0].args.at("path") == "src/auth.ts");
        assert(!decoded.tool_calls[0].method.has_value());

        assert(decoded.tool_calls[1].name == "write");
        assert(decoded.tool_calls[1].method.has_value());
        assert(decoded.tool_calls[1].method.value() == "commit");
        assert(decoded.tool_calls[1].args.at("path") == "src/auth.ts");
        assert(decoded.tool_calls[1].args.at("content") == "new validation code");

        std::vector<std::string> arg_order;
        for (const auto& p : decoded.tool_calls[1].args) arg_order.push_back(p.first);
        std::vector<std::string> want_arg_order = {"path", "content"};
        assert(arg_order == want_arg_order);

        std::cout << "Result: PASS (order + args + method round-trip)\n\n";
    }

    // Test 7: Bounded varint decoding (reject long varints)
    {
        std::cout << "[TEST 7] Bounded varint decoding\n";
        BinaryEncoder encoder;

        std::vector<uint8_t> malformed_varint = {0x80, 0x80, 0x80, 0x80, 0x80, 0x80};
        bool caught = false;
        try {
            std::vector<uint8_t> header_buf = {0x4C, 0x4C, 0x4D, 0x54, 0x01};
            header_buf.push_back(static_cast<uint8_t>(BinaryEncoder::Opcode::OP_VERSION));
            header_buf.insert(header_buf.end(), malformed_varint.begin(), malformed_varint.end());

            size_t pos = 0;
            encoder.decode_header(header_buf, pos);
        } catch (const std::runtime_error& e) {
            std::string msg = e.what();
            if (msg.find("Varint too long") != std::string::npos) caught = true;
        }
        assert(caught);
        std::cout << "Result: PASS (Successfully rejected malicious varint)\n\n";
    }

    // Test 8: a 5-byte varint that overflows 32 bits must be rejected, not wrapped
    {
        std::cout << "[TEST 8] 32-bit varint overflow rejected\n";
        BinaryEncoder encoder;
        std::vector<uint8_t> buf = {0x11, 0x81, 0x80, 0x80, 0x80, 0x10, 0xAA};
        size_t pos = 0;
        bool caught = false;
        try {
            encoder.decode_statement(buf, pos);
        } catch (const std::runtime_error&) {
            caught = true;
        }
        assert(caught);
        std::cout << "Result: PASS (Successfully rejected overflowing varint)\n\n";
    }

    std::cout << "All binary encoder tests passed!\n";
    return 0;
}
