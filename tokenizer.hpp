#pragma once
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <fstream>
#include <stdexcept>
#include <cstdint>
#include <climits>
#include <array>
#include <cctype>
#include <algorithm>
#include <functional>

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
//
// Because the ASCII specialization would silently produce a *wrong* count on
// non-ASCII input rather than an obviously broken one, encode() rejects any byte
// >= 0x80 outright. A published measurement that is quietly off by a few tokens
// is worse than one that failed to run.
class Cl100kTokenizer {
public:
    // Transparent hashing so the merge loop can probe the rank table with a
    // std::string_view over the input. Without this, every candidate pair would
    // have to be materialized as a temporary std::string just to be looked up
    // and thrown away -- which is most of the allocation in tokenization.
    struct StringHash {
        using is_transparent = void;
        size_t operator()(std::string_view sv) const noexcept {
            return std::hash<std::string_view>{}(sv);
        }
    };
    struct StringEq {
        using is_transparent = void;
        bool operator()(std::string_view a, std::string_view b) const noexcept { return a == b; }
    };
    using RankMap = std::unordered_map<std::string, int, StringHash, StringEq>;

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
        // Pointers into unordered_map keys stay valid across rehash, and nothing
        // ever erases from ranks_, so the inverse map can borrow rather than copy.
        inverse_.reserve(ranks_.size());
        for (const auto& kv : ranks_) {
            inverse_[kv.second] = &kv.first;
        }
    }

    std::vector<int> encode(const std::string& text) const {
        require_ascii(text);
        std::vector<int> out;
        std::string_view view(text);
        size_t i = 0, n = text.size();
        while (i < n) {
            size_t len = next_pretoken(text, i); // guaranteed >= 1
            bpe(view.substr(i, len), out);       // a view, not a copy
            i += len;
        }
        return out;
    }

    size_t count(const std::string& text) const { return encode(text).size(); }

    // Inverse of encode(). Concatenating the byte sequences behind `ids` must
    // reproduce the original text exactly; the tests use that round trip to catch
    // a pre-tokenizer that drops or duplicates input.
    std::string decode(const std::vector<int>& ids) const {
        std::string out;
        for (int id : ids) {
            auto it = inverse_.find(id);
            if (it == inverse_.end()) {
                throw std::runtime_error("Cl100kTokenizer: unknown token id in decode");
            }
            out += *it->second;
        }
        return out;
    }

    // The pre-token split that encode() merges within. Exposed because this is
    // the hand-written half of the cl100k_base pattern, and therefore where
    // protocol punctuation (`:` `;` `=` `[` `]` runs) is most likely mis-split.
    std::vector<std::string> pretokens(const std::string& text) const {
        require_ascii(text);
        std::vector<std::string> out;
        size_t i = 0, n = text.size();
        while (i < n) {
            size_t len = next_pretoken(text, i);
            out.push_back(text.substr(i, len));
            i += len;
        }
        return out;
    }

    // The loaded vocabulary (token bytes -> id). Exposed so the tests can run an
    // independent reference merge against the same ranks.
    const RankMap& ranks() const { return ranks_; }

private:
    RankMap ranks_;
    std::unordered_map<int, const std::string*> inverse_;

    static void require_ascii(const std::string& text) {
        for (size_t i = 0; i < text.size(); ++i) {
            if (static_cast<unsigned char>(text[i]) >= 0x80) {
                throw std::runtime_error(
                    "Cl100kTokenizer: non-ASCII byte at offset " + std::to_string(i) +
                    "; this tokenizer is ASCII-only and would mis-count the input");
            }
        }
    }

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

    static constexpr uint32_t kNone = UINT32_MAX;

    struct MergePair {
        int rank;
        uint32_t index;
        bool operator>(const MergePair& other) const {
            if (rank != other.rank) return rank > other.rank;
            return index > other.index;   // leftmost wins ties, as tiktoken does
        }
    };

    // A node is a half-open range [start, start+len) into the pre-token.
    //
    // The key invariant: a merge only ever joins two *adjacent* nodes, so every
    // node's range stays contiguous in the original piece. That means the
    // concatenation of node i and node j is just the range starting at i.start
    // with length i.len + j.len -- no bytes need to be copied to look it up.
    struct Node {
        uint32_t start;
        uint32_t len;
        uint32_t prev;
        uint32_t next;
        bool active;
    };

    // Byte-pair merge one pre-token, appending resulting token ids to `out`.
    // tiktoken's algorithm: start from single bytes, repeatedly merge the adjacent
    // pair with the lowest rank until no adjacent pair is mergeable. Implemented
    // as an O(n log n) heap over candidate pairs rather than a rescan.
    //
    // Nodes carry (start, len) rather than a std::string, and candidate pairs are
    // probed as string_views over the piece, so a merge allocates nothing. The
    // previous version built a temporary std::string for every probe and appended
    // to a per-node string on every merge; this loop runs over every byte of every
    // payload the benchmarks measure.
    void bpe(std::string_view piece, std::vector<int>& out) const {
        if (piece.empty()) return;
        if (piece.size() == 1) {
            auto it = ranks_.find(piece);
            if (it == ranks_.end()) throw std::runtime_error("Cl100kTokenizer: byte sequence not in ranks");
            out.push_back(it->second);
            return;
        }

        // Scratch buffers reused across calls. bpe() runs once per pre-token, so
        // a fresh vector per call would allocate several times per line of input.
        static thread_local std::vector<Node> nodes;
        static thread_local std::vector<MergePair> heap;
        const uint32_t n = static_cast<uint32_t>(piece.size());
        nodes.clear();
        nodes.resize(n);
        heap.clear();

        for (uint32_t i = 0; i < n; ++i) {
            nodes[i] = Node{ i, 1, (i == 0) ? kNone : i - 1, (i + 1 < n) ? i + 1 : kNone, true };
        }

        const auto cmp = std::greater<MergePair>{};

        auto push_pair = [&](uint32_t i) {
            if (i == kNone || !nodes[i].active) return;
            const uint32_t j = nodes[i].next;
            if (j == kNone || !nodes[j].active) return;
            // Contiguity invariant makes this the concatenation of i and j.
            const std::string_view cand(piece.data() + nodes[i].start, nodes[i].len + nodes[j].len);
            auto it = ranks_.find(cand);
            if (it != ranks_.end()) {
                heap.push_back(MergePair{ it->second, i });
                std::push_heap(heap.begin(), heap.end(), cmp);
            }
        };

        for (uint32_t i = 0; i + 1 < n; ++i) push_pair(i);

        while (!heap.empty()) {
            std::pop_heap(heap.begin(), heap.end(), cmp);
            const MergePair top = heap.back();
            heap.pop_back();

            const uint32_t i = top.index;
            if (!nodes[i].active) continue;
            const uint32_t j = nodes[i].next;
            if (j == kNone || !nodes[j].active) continue;

            // The heap can hold entries that a later merge invalidated. Re-probe
            // and drop any whose rank no longer matches what was queued.
            const std::string_view cand(piece.data() + nodes[i].start, nodes[i].len + nodes[j].len);
            auto it = ranks_.find(cand);
            if (it == ranks_.end() || it->second != top.rank) continue;

            nodes[i].len += nodes[j].len;
            nodes[j].active = false;
            nodes[i].next = nodes[j].next;
            if (nodes[j].next != kNone) nodes[nodes[j].next].prev = i;

            push_pair(nodes[i].prev);
            push_pair(i);
        }

        for (uint32_t curr = 0; curr != kNone; curr = nodes[curr].next) {
            if (!nodes[curr].active) continue;
            const std::string_view tok(piece.data() + nodes[curr].start, nodes[curr].len);
            auto it = ranks_.find(tok);
            if (it == ranks_.end()) {
                throw std::runtime_error("Cl100kTokenizer: byte sequence not in ranks");
            }
            out.push_back(it->second);
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
