#include <iostream>
#include "test_harness.hpp"
#include <vector>
#include <string>
#include "tokenizer.hpp"

#ifndef CL100K_RANKS_PATH
#define CL100K_RANKS_PATH "data/cl100k_base.tiktoken"
#endif

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

    std::cout << "\nAll tokenizer tests passed!\n";
    return TEST_SUMMARY("tokenizer_tests");
}
