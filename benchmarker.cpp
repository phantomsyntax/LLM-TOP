#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <iomanip>
#include <cctype>

// A heuristic token estimator mimicking BPE
// Rules: Words are tokens. Punctuation are tokens. Spaces are absorbed or separate.
int estimateTokens(const std::string& text) {
    int count = 0;
    bool in_word = false;
    int word_len = 0;
    for (char c : text) {
        if (std::isalnum(c)) {
            if (!in_word) {
                count++;
                in_word = true;
                word_len = 0;
            }
            word_len++;
            // Add extra token penalty for very long words (camelCase/paths)
            // Simulates BPE subword splitting: every 5 chars adds a subword token
            if (word_len > 0 && word_len % 5 == 0) { count++; }
        } else if (std::isspace(c)) {
            in_word = false;
            word_len = 0;
        } else {
            // Punctuation is usually its own token in BPE
            count++;
            in_word = false;
            word_len = 0;
        }
    }
    return count;
}

int main() {
    std::string top_payload = 
        "VER:LLM-TOPv1 CHK:sha256:abcd AGT:ci UID:anon TIM:2026-07-18 REQID:1 FALLBACK:json\n"
        "[RSH] tgt:src/auth.ts:cap=abc;ttl=999 act:refactor GL:fix_auth TD:add_tests\n"
        "!read[path=$P/auth.ts]\n"
        "!run[target=tests.ts]>test\n";

    std::string json_payload = R"({
  "version": "LLM-TOPv1",
  "checksum": "sha256:abcd",
  "agent": "ci",
  "uid": "anon",
  "time": "2026-07-18",
  "reqid": "1",
  "fallback": "json",
  "statements": [
    {
      "role": "RSH",
      "kvpairs": {
        "tgt": "src/auth.ts:cap=abc;ttl=999",
        "act": "refactor",
        "GL": "fix_auth",
        "TD": "add_tests"
      },
      "commands": [
        {
          "tool": "read",
          "args": { "path": "$P/auth.ts" }
        },
        {
          "tool": "run",
          "method": "test",
          "args": { "target": "tests.ts" }
        }
      ]
    }
  ]
})";

    size_t top_chars = top_payload.length();
    size_t json_chars = json_payload.length();
    
    int top_tokens = estimateTokens(top_payload);
    int json_tokens = estimateTokens(json_payload);

    std::cout << "=========================================\n";
    std::cout << "      LLM-TOP vs JSON BENCHMARK\n";
    std::cout << "=========================================\n\n";

    std::cout << std::left << std::setw(20) << "Metric" 
              << std::setw(15) << "LLM-TOP" 
              << std::setw(15) << "JSON" 
              << "Reduction %\n";
    std::cout << std::string(60, '-') << "\n";

    float char_reduction = 100.0f * (1.0f - (float)top_chars / json_chars);
    std::cout << std::left << std::setw(20) << "Characters (Bytes)" 
              << std::setw(15) << top_chars 
              << std::setw(15) << json_chars 
              << std::fixed << std::setprecision(1) << char_reduction << "%\n";

    float token_reduction = 100.0f * (1.0f - (float)top_tokens / json_tokens);
    std::cout << std::left << std::setw(20) << "Est. Tokens (BPE)" 
              << std::setw(15) << top_tokens 
              << std::setw(15) << json_tokens 
              << std::fixed << std::setprecision(1) << token_reduction << "%\n";

    std::cout << "=========================================\n";
    
    return 0;
}
