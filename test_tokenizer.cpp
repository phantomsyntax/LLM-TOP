#include <iostream>
#include "test_harness.hpp"
#include <vector>
#include <string>
#include <unordered_map>
#include <climits>
#include "tokenizer.hpp"

#ifndef CL100K_RANKS_PATH
#define CL100K_RANKS_PATH "data/cl100k_base.tiktoken"
#endif

// An independent, deliberately naive restatement of tiktoken's byte-pair merge:
// start from single bytes and repeatedly merge the adjacent pair with the lowest
// rank, leftmost on ties, until nothing is mergeable. It is O(n^2) and obviously
// correct, which is the point -- tokenizer.hpp's priority-queue version is the
// fast one, and every published token count depends on the two agreeing.
static std::vector<int> reference_bpe(const Cl100kTokenizer::RankMap& ranks,
                                      const std::string& piece) {
    std::vector<std::string> parts;
    parts.reserve(piece.size());
    for (char c : piece) parts.emplace_back(1, c);

    while (parts.size() > 1) {
        int best_rank = INT_MAX;
        size_t best_i = SIZE_MAX;
        for (size_t i = 0; i + 1 < parts.size(); ++i) {
            auto it = ranks.find(parts[i] + parts[i + 1]);
            if (it != ranks.end() && it->second < best_rank) {  // strict: leftmost wins ties
                best_rank = it->second;
                best_i = i;
            }
        }
        if (best_i == SIZE_MAX) break;
        parts[best_i] += parts[best_i + 1];
        parts.erase(parts.begin() + static_cast<long>(best_i) + 1);
    }

    std::vector<int> out;
    out.reserve(parts.size());
    for (const auto& p : parts) out.push_back(ranks.at(p));
    return out;
}

// Payloads in the shapes this project actually measures. Protocol punctuation
// (`:` `;` `=` `[` `]` `/` runs) is dense here and rare in prose, so it is the
// part of the hand-written pre-tokenizer least exercised by the word-based
// vectors above.
static const std::vector<std::string>& protocol_corpus() {
    static const std::vector<std::string> corpus = {
        "VER:LLM-TOPv1 CHK:sha256:1234 AGT:coder UID:anon TIM:2026-07-18 REQID:req_refactor FALLBACK:json\n"
        "[CODER] tgt:src/auth.ts:cap=secret;ttl=3600 act:refactor GL:improve_validation\n"
        "!read[path=src/auth.ts]\n",

        "[EXEC] tgt:build/run.sh act:execute GL:run_suite\n"
        "!run[target=build/run.sh;args=--config=Release;timeout=120]\n",

        "{\"version\":\"LLM-TOPv1\",\"statements\":[{\"role\":\"CODER\","
        "\"kvpairs\":{\"tgt\":\"src/auth.ts\",\"act\":\"refactor\"},"
        "\"commands\":[{\"tool\":\"read\",\"args\":{\"path\":\"src/auth.ts\"}}]}]}",

        "version: LLM-TOPv1\n"
        "statements:\n"
        "  - role: CODER\n"
        "    kvpairs:\n"
        "      tgt: src/auth.ts\n"
        "      act: refactor\n",

        "]]\n[EXEC]",
        ";;;===[[[]]]:::",
        "ttl=3600 exp=1795000000 iat=0",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyZWFkZXIifQ.sig_hash",
    };
    return corpus;
}

// Ground-truth token ids taken directly from data/cl100k_base.tiktoken:
//   "hello"  -> 15339   (base64 aGVsbG8=)
//   " world" -> 1917    (base64 IHdvcmxk)
//   " hello" -> 24748   (base64 IGhlbGxv)
// If the pre-tokenizer or the byte-pair merge is wrong, these exact ids will not
// be reproduced, so each assertion fails loudly rather than silently mis-counting.
int main() {
    std::cout << "Running cl100k tokenizer tests...\n\n";
    Cl100kTokenizer tok(CL100K_RANKS_PATH);

    // Test 1: a single word encodes to its known cl100k id
    {
        auto ids = tok.encode("hello");
        CHECK_EQ(ids.size(), 1);
        CHECK_EQ(ids[0], 15339);
        std::cout << "[TEST 1] 'hello' -> [15339] PASS\n";
    }

    // Test 2: two words; the space between them attaches to the following word
    {
        auto ids = tok.encode("hello world");
        CHECK_EQ(ids.size(), 2);
        CHECK_EQ(ids[0], 15339);
        CHECK_EQ(ids[1], 1917);
        std::cout << "[TEST 2] 'hello world' -> [15339, 1917] PASS\n";
    }

    // Test 3: a leading space is part of the same pre-token as the word
    {
        auto ids = tok.encode(" hello");
        CHECK_EQ(ids.size(), 1);
        CHECK_EQ(ids[0], 24748);
        std::cout << "[TEST 3] ' hello' -> [24748] PASS\n";
    }

    // Test 4: empty input produces no tokens
    {
        auto ids = tok.encode("");
        CHECK(ids.empty());
        std::cout << "[TEST 4] '' -> [] PASS\n";
    }

    // Test 5: count() is consistent with encode() and non-zero for real payloads
    {
        std::string s = "VER:LLM-TOPv1 act:refactor GL:fix_leak";
        CHECK_EQ(tok.count(s), tok.encode(s).size());
        CHECK(tok.count(s) > 0);
        std::cout << "[TEST 5] count() == encode().size() PASS\n";
    }

    // Test 6: tiktoken's own README example. Ids verified directly against the
    // ranks file: exercises subword splitting ("tiktoken" -> "t","ik","token")
    // and single-token punctuation ("!").
    {
        auto ids = tok.encode("tiktoken is great!");
        std::vector<int> expected = {83, 1609, 5963, 374, 2294, 0};
        CHECK_EQ(ids, expected);
        std::cout << "[TEST 6] 'tiktoken is great!' -> [83,1609,5963,374,2294,0] PASS\n";
    }

    // Test 7 (T6): pre-token boundaries across an LLM-TOP header. Derived by
    // hand from the cl100k_base pattern: a lone `:` before a digit cannot attach
    // to a following word, and digit runs split into groups of at most three --
    // so "sha256:1234" is four tokens, not two.
    {
        auto parts = tok.pretokens("VER:LLM-TOPv1 CHK:sha256:1234");
        std::vector<std::string> expected = {
            "VER", ":LLM", "-TOPv", "1", " CHK", ":sha", "256", ":", "123", "4"
        };
        CHECK_EQ(parts, expected);
        std::cout << "[TEST 7] header pre-token split PASS\n";
    }

    // Test 8 (T6): tool-call syntax. Every delimiter binds forward onto the word
    // that follows it, so `[`, `=`, `;` and `/` cost nothing beyond the word
    // they lead -- but a closing `]` with nothing after it stands alone.
    {
        auto parts = tok.pretokens("!read[path=src/a.ts;cap=x]");
        std::vector<std::string> expected = {
            "!read", "[path", "=src", "/a", ".ts", ";cap", "=x", "]"
        };
        CHECK_EQ(parts, expected);
        std::cout << "[TEST 8] tool-call pre-token split PASS\n";
    }

    // Test 9 (T6): a punctuation run absorbs the newlines that follow it, which
    // is what keeps statement-per-line framing cheap.
    {
        auto parts = tok.pretokens("]]\n[EXEC]");
        std::vector<std::string> expected = {"]]\n", "[EXEC", "]"};
        CHECK_EQ(parts, expected);
        std::cout << "[TEST 9] punctuation run absorbs trailing newline PASS\n";
    }

    // Test 10 (T6): the fast merge loop agrees with the naive reference on every
    // corpus payload. This is the assertion that makes the published numbers
    // trustworthy, and the one that will catch a regression when the merge loop
    // is optimized.
    {
        size_t mismatches = 0;
        for (const auto& payload : protocol_corpus()) {
            std::vector<int> expected;
            for (const auto& piece : tok.pretokens(payload)) {
                for (int id : reference_bpe(tok.ranks(), piece)) expected.push_back(id);
            }
            if (tok.encode(payload) != expected) ++mismatches;
        }
        CHECK_EQ(mismatches, 0);
        std::cout << "[TEST 10] fast merge == reference merge on " << protocol_corpus().size()
                  << " protocol payloads PASS\n";
    }

    // Test 11 (T6): decoding the ids reproduces the input byte for byte. A
    // pre-tokenizer that dropped or duplicated a character would still return a
    // plausible-looking count, and only this catches it.
    {
        size_t roundtrip_failures = 0;
        for (const auto& payload : protocol_corpus()) {
            if (tok.decode(tok.encode(payload)) != payload) ++roundtrip_failures;
        }
        CHECK_EQ(roundtrip_failures, 0);
        std::cout << "[TEST 11] decode(encode(x)) == x on all corpus payloads PASS\n";
    }

    // Test 12 (T6): the ASCII-only limitation is enforced, not just documented.
    // On non-ASCII this tokenizer would return a wrong count rather than an
    // obviously broken one, so it refuses instead.
    {
        CHECK_THROWS_WITH(tok.encode("caf\xC3\xA9"), "non-ASCII");
        CHECK(tok.count("cafe") > 0);  // the same word, ASCII-only, still counts
        std::cout << "[TEST 12] non-ASCII input is rejected, not mis-counted PASS\n";
    }

    std::cout << "\nAll tokenizer tests passed!\n";
    return TEST_SUMMARY("tokenizer_tests");
}
