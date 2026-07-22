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

// ordered_map::operator[] hands out a reference into its backing sequence. With
// a vector behind it, any later insertion could reallocate and leave that
// reference dangling -- undefined behavior that happens to work until it does
// not. The container is a deque now, where appending never invalidates
// references to existing elements.
void test_ordered_map_reference_survives_growth() {
    ordered_map m;
    std::string& first = m["tgt"];
    first = "src/main.cpp";

    // Enough insertions to force many reallocations under the old vector.
    for (int i = 0; i < 256; ++i) {
        m["k" + std::to_string(i)] = "v" + std::to_string(i);
    }

    // Writing through the original reference must still reach the same entry.
    first = "src/other.cpp";
    CHECK_EQ(m.at("tgt"), std::string("src/other.cpp"));
    CHECK_EQ(m.size(), 257u);

    // Insertion order is still the point of this container.
    CHECK_EQ(m.begin()->first, std::string("tgt"));

    // insert_or_assign overwrites, which is what its name now promises.
    m.insert_or_assign({"tgt", "src/third.cpp"});
    CHECK_EQ(m.at("tgt"), std::string("src/third.cpp"));
    CHECK_EQ(m.size(), 257u);

    // erase compacts and keeps the remaining index consistent.
    m.erase("k0");
    CHECK_EQ(m.size(), 256u);
    CHECK_EQ(m.at("k255"), std::string("v255"));
    CHECK_EQ(m.count("k0"), 0u);

    std::cout << "[PASS] ordered_map references survive growth\n";
}

// Six live models were asked for the same two-action frame. Two produced
// semantically perfect output that the parser rejected on punctuation alone:
// nemotron used '=' where the statement line wanted ':', and mistral-large-3
// put every header field on its own line. Both are accepted now. These tests
// pin the leniency AND its limits -- the limits are the part that can rot.
void test_equals_accepted_as_kv_separator() {
    LLMTOPParser parser(LLMTOPParser::Mode::STRICT);

    // nemotron-3-super's actual output shape.
    std::string frame =
        "VER:LLM-TOPv1 CHK:sha256:0000 AGT:planner UID:user1 TIM:2026-07-22 REQID:probe FALLBACK:json\n"
        "[CODER] tgt=src/a.cpp act=read GL=read_src_a_cpp\n"
        "!read[path=src/a.cpp]\n";
    AST ast = parser.parse(frame);
    CHECK_EQ(ast.statements.size(), 1u);
    CHECK_EQ(ast.statements[0].kvpairs["tgt"], "src/a.cpp");
    CHECK_EQ(ast.statements[0].kvpairs["act"], "read");
    CHECK_EQ(ast.statements[0].kvpairs["GL"], "read_src_a_cpp");

    // The earliest separator wins. A ':' introducing the value must not lose to
    // an '=' that appears later inside a capability token -- that would split
    // the pair in the wrong place and silently change the authorized target.
    AST ast2 = parser.parse(
        "VER:LLM-TOPv1 CHK:sha256:0000 AGT:planner UID:user1 TIM:2026-07-22 REQID:r FALLBACK:json\n"
        "[CODER] tgt:src/a.cpp:cap=jwt.tok.sig act:read\n");
    CHECK_EQ(ast2.statements.size(), 1u);
    CHECK_EQ(ast2.statements[0].kvpairs["tgt"], "src/a.cpp:cap=jwt.tok.sig");

    // A token carrying neither separator is still an error.
    LLMTOPParser tolerant(LLMTOPParser::Mode::TOLERANT);
    AST ast3 = tolerant.parse(
        "VER:LLM-TOPv1 CHK:sha256:0000 AGT:planner UID:user1 TIM:2026-07-22 REQID:r FALLBACK:json\n"
        "[CODER] bareword act:read\n");
    CHECK(ast3.diagnostic.find("bareword") != std::string::npos);

    // Regression: mistral-large-3 put the tool call on the statement line. The
    // first cut of the '=' rule split `!read[path=src/a.cpp]` into the pair
    // `!read[path` = `src/a.cpp]`, so the statement validated with NO tool call
    // -- a frame that authorizes nothing, reported as well formed. '=' must bind
    // only after a bare identifier, so this has to be refused outright.
    bool refused = false;
    try {
        parser.parse(
            "VER:LLM-TOPv1 CHK:sha256:0000 AGT:planner UID:user1 TIM:2026-07-22 REQID:r FALLBACK:json\n"
            "[CODER] tgt:src/a.cpp act:read GL:read_source_a !read[path=src/a.cpp]\n");
    } catch (const std::runtime_error&) { refused = true; }
    CHECK(refused);

    // The same guard must not block a legitimate key that merely sits next to a
    // capability: here the ':' is the real separator and the '=' is data.
    AST ast4 = parser.parse(
        "VER:LLM-TOPv1 CHK:sha256:0000 AGT:planner UID:user1 TIM:2026-07-22 REQID:r FALLBACK:json\n"
        "[CODER] tgt:src/a.cpp:cap=jwt.tok.sig act=read\n");
    CHECK_EQ(ast4.statements[0].kvpairs["tgt"], "src/a.cpp:cap=jwt.tok.sig");
    CHECK_EQ(ast4.statements[0].kvpairs["act"], "read");
}

void test_multiline_header_is_folded() {
    LLMTOPParser parser(LLMTOPParser::Mode::STRICT);

    // mistral-large-3's actual output shape: one header field per line.
    std::string frame =
        "VER:LLM-TOPv1\nCHK:sha256:0000\nAGT:planner\nUID:user1\n"
        "TIM:2026-07-22\nREQID:probe\nFALLBACK:json\n"
        "[CODER] tgt:src/a.cpp act:read GL:inspect_source_file\n"
        "!read[path=src/a.cpp]\n"
        "[CODER] tgt:src/b.cpp act:edit GL:modify_source_file\n"
        "!write[path=src/b.cpp]\n";
    AST ast = parser.parse(frame);
    CHECK_EQ(ast.header.ver, "LLM-TOPv1");
    CHECK_EQ(ast.header.agt, "planner");
    CHECK_EQ(ast.header.reqid, "probe");
    CHECK_EQ(ast.statements.size(), 2u);
    CHECK_EQ(ast.statements[0].kvpairs["tgt"], "src/a.cpp");
    CHECK_EQ(ast.statements[1].tool_calls.size(), 1u);

    // Folding must stop at the first non-header line. A statement KV line is
    // also space-free and colon-bearing, so only the known-key check keeps
    // `tgt:` out of the header -- if that check is ever dropped, the statement
    // silently loses its target instead of failing loudly.
    AST ast2 = parser.parse(
        "VER:LLM-TOPv1 CHK:sha256:0000 AGT:planner UID:user1 TIM:2026-07-22 REQID:r FALLBACK:json\n"
        "[CODER] act:read\n"
        "tgt:src/a.cpp\n");
    CHECK_EQ(ast2.statements.size(), 1u);
    CHECK_EQ(ast2.statements[0].kvpairs["tgt"], "src/a.cpp");

    // The frame is unchanged as far as CHK is concerned: folding is a parse-time
    // view, not a rewrite, so the digest still covers the bytes that arrived.
    CHECK_EQ(ast.raw_frame, frame);
}

int main() {
    std::cout << "Running LLM-TOP Parser Tests v3...\n";
    test_equals_accepted_as_kv_separator();
    test_multiline_header_is_folded();
    test_ordered_map_reference_survives_growth();
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
