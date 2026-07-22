#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <fstream>
#include <stdexcept>
#include <cstdint>
#include <climits>
#include <array>
#include <cctype>
#include <queue>

// Self-contained cl100k_base (tiktoken) BPE tokenizer.
//
// Loads the vendored ranks file (data/cl100k_base.tiktoken), whose lines are
// "<base64(token_bytes)> <rank>", then reproduces tiktoken's encoding:
//   1. split the text into pre-tokens with the cl100k_base pattern (hand-coded
//      here and specialized for ASCII payloads);
//   2. within each pre-token, run byte-pair merging by ascending rank.
//
// This is intended for measuring token counts of ASCII protocol/JSON/YAML
// payloads. It is not a general Unicode tokenizer: \p{L}/\p{N}/\s are treated as
// their ASCII subsets, which is exact for ASCII input and the reason the
// known-vector tests in test_tokenizer.cpp pass.
class Cl100kTokenizer {
public:
    explicit Cl100kTokenizer(const std::string& ranks_path) {
        std::ifstream in(ranks_path, std::ios::binary);
        if (!in) {
            throw std::runtime_error("Cl100kTokenizer: cannot open ranks file: " + ranks_path);
        }
        std::string line;
        while (std::getline(in, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back(); // tolerate CRLF
            if (line.empty()) continue;
            size_t sp = line.find(' ');
            if (sp == std::string::npos) continue;
            std::string token = base64_decode(line.substr(0, sp));
            int rank = std::stoi(line.substr(sp + 1));
            ranks_[token] = rank;
        }
        if (ranks_.empty()) {
            throw std::runtime_error("Cl100kTokenizer: ranks file was empty: " + ranks_path);
        }
    }

    std::vector<int> encode(const std::string& text) const {
        std::vector<int> out;
        size_t i = 0, n = text.size();
        while (i < n) {
            size_t len = next_pretoken(text, i); // guaranteed >= 1
            bpe(text.substr(i, len), out);
            i += len;
        }
        return out;
    }

    size_t count(const std::string& text) const { return encode(text).size(); }

private:
    std::unordered_map<std::string, int> ranks_;

    // --- character classes (ASCII-specialized) ---
    static bool is_letter(unsigned char c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }
    static bool is_digit(unsigned char c)  { return c >= '0' && c <= '9'; }
    static bool is_space(unsigned char c)  { return c==' '||c=='\t'||c=='\n'||c=='\r'||c=='\v'||c=='\f'; }
    static bool is_nl(unsigned char c)     { return c == '\r' || c == '\n'; }

    // Length (>= 1) of the next pre-token at position i, following the ordered
    // alternatives of the cl100k_base pattern:
    //   (?i:'s|'t|'re|'ve|'m|'ll|'d)
    //   | [^\r\n\p{L}\p{N}]?\p{L}+
    //   | \p{N}{1,3}
    //   |  ?[^\s\p{L}\p{N}]+[\r\n]*
    //   | \s*[\r\n]+  |  \s+(?!\S)  |  \s+
    size_t next_pretoken(const std::string& s, size_t i) const {
        size_t n = s.size();
        unsigned char c = (unsigned char)s[i];

        // 1. contractions: '(s|t|re|ve|m|ll|d), case-insensitive
        if (c == '\'' && i + 1 < n) {
            unsigned char d = (unsigned char)std::tolower((unsigned char)s[i + 1]);
            if (d=='s' || d=='t' || d=='m' || d=='d') return 2;
            if (i + 2 < n) {
                unsigned char e = (unsigned char)std::tolower((unsigned char)s[i + 2]);
                if ((d=='r'&&e=='e') || (d=='v'&&e=='e') || (d=='l'&&e=='l')) return 3;
            }
        }

        // 2. optional single non-letter/non-digit/non-CRLF char, then one+ letters
        {
            size_t opt = (!is_nl(c) && !is_letter(c) && !is_digit(c)) ? 1 : 0;
            size_t k = i + opt, m = 0;
            while (k + m < n && is_letter((unsigned char)s[k + m])) m++;
            if (m >= 1) return opt + m;
        }

        // 3. 1..3 digits
        if (is_digit(c)) {
            size_t m = 0;
            while (m < 3 && i + m < n && is_digit((unsigned char)s[i + m])) m++;
            return m;
        }

        // 4. optional space, then one+ symbol chars, then trailing CR/LF
        {
            size_t opt = (c == ' ') ? 1 : 0;
            size_t k = i + opt, p = 0;
            while (k + p < n) {
                unsigned char x = (unsigned char)s[k + p];
                if (is_space(x) || is_letter(x) || is_digit(x)) break;
                p++;
            }
            if (p >= 1) {
                size_t q = 0;
                while (k + p + q < n && is_nl((unsigned char)s[k + p + q])) q++;
                return opt + p + q;
            }
        }

        // 5/6/7. whitespace run
        if (is_space(c)) {
            size_t run = 0;
            long last_nl = -1;
            while (i + run < n && is_space((unsigned char)s[i + run])) {
                if (is_nl((unsigned char)s[i + run])) last_nl = (long)run;
                run++;
            }
            // \s*[\r\n]+ : run contains a newline -> consume through the last newline;
            // trailing spaces become the next pre-token.
            if (last_nl >= 0) return (size_t)last_nl + 1;
            // \s+(?!\S) | \s+ : pure non-newline whitespace -> the whole run.
            return run;
        }

        return 1; // safety: never return 0
    }

    // Byte-pair merge one pre-token, appending resulting token ids to `out`.
    // tiktoken's algorithm: start from single bytes, repeatedly merge the adjacent
    // pair with the lowest rank until no adjacent pair is mergeable.
#include <queue>

    struct MergePair {
        int rank;
        size_t index;
        bool operator>(const MergePair& other) const {
            if (rank != other.rank) return rank > other.rank;
            return index > other.index;
        }
    };

    // Byte-pair merge one pre-token, appending resulting token ids to `out`.
    // Fast O(n log n) priority queue implementation matching tiktoken's min-rank pair selection.
    void bpe(const std::string& piece, std::vector<int>& out) const {
        if (piece.empty()) return;
        if (piece.size() == 1) {
            auto it = ranks_.find(piece);
            if (it == ranks_.end()) throw std::runtime_error("Cl100kTokenizer: byte sequence not in ranks");
            out.push_back(it->second);
            return;
        }

        struct Node {
            std::string str;
            size_t prev;
            size_t next;
            bool active = true;
        };

        std::vector<Node> nodes(piece.size());
        for (size_t i = 0; i < piece.size(); ++i) {
            nodes[i].str = std::string(1, piece[i]);
            nodes[i].prev = (i == 0) ? SIZE_MAX : i - 1;
            nodes[i].next = (i + 1 < piece.size()) ? i + 1 : SIZE_MAX;
        }

        std::priority_queue<MergePair, std::vector<MergePair>, std::greater<MergePair>> pq;

        auto check_pair = [&](size_t i) {
            if (i == SIZE_MAX || nodes[i].next == SIZE_MAX || !nodes[i].active || !nodes[nodes[i].next].active) return;
            auto it = ranks_.find(nodes[i].str + nodes[nodes[i].next].str);
            if (it != ranks_.end()) {
                pq.push({it->second, i});
            }
        };

        for (size_t i = 0; i + 1 < piece.size(); ++i) {
            check_pair(i);
        }

        while (!pq.empty()) {
            auto top = pq.top();
            pq.pop();

            size_t i = top.index;
            if (!nodes[i].active || nodes[i].next == SIZE_MAX || !nodes[nodes[i].next].active) continue;

            // Re-verify current rank matches
            size_t j = nodes[i].next;
            auto it = ranks_.find(nodes[i].str + nodes[j].str);
            if (it == ranks_.end() || it->second != top.rank) continue;

            // Perform merge of nodes[i] and nodes[j]
            nodes[i].str += nodes[j].str;
            nodes[j].active = false;
            nodes[i].next = nodes[j].next;
            if (nodes[j].next != SIZE_MAX) {
                nodes[nodes[j].next].prev = i;
            }

            // Push updated neighbor pairs
            check_pair(nodes[i].prev);
            check_pair(i);
        }

        size_t curr = 0;
        while (curr != SIZE_MAX) {
            if (nodes[curr].active) {
                auto it = ranks_.find(nodes[curr].str);
                if (it == ranks_.end()) {
                    throw std::runtime_error("Cl100kTokenizer: byte sequence not in ranks");
                }
                out.push_back(it->second);
            }
            curr = nodes[curr].next;
        }
    }

    // --- standard base64 decode (RFC 4648, '+'/'/' alphabet, '=' padding) ---
    static std::string base64_decode(const std::string& in) {
        static const std::array<int, 256> lut = []{
            std::array<int, 256> t{}; t.fill(-1);
            const char* a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            for (int i = 0; i < 64; i++) t[(unsigned char)a[i]] = i;
            return t;
        }();
        std::string out;
        int val = 0, bits = -8;
        for (unsigned char c : in) {
            if (c == '=') break;
            int d = lut[c];
            if (d < 0) continue;
            val = (val << 6) | d;
            bits += 6;
            if (bits >= 0) {
                out.push_back((char)((val >> bits) & 0xFF));
                bits -= 8;
            }
        }
        return out;
    }
};
