#pragma once
#include "parser_v2.hpp"
#include "sha256.hpp"
#include "chk.hpp"
#include "time_utils.hpp"
#include <iostream>
#include <chrono>
#include <string>
#include <stdexcept>
#include <unordered_map>
#include <memory>
#include <array>
#include <vector>
#include <deque>
#include <string_view>
#include <sstream>
#include <mutex>
#include <functional>
#include <cctype>
#include <atomic>
#include <utility>

// JWT validator for capability tokens.
//
// This build ships exactly one signature algorithm: HMAC-SHA256 ("HS256").
// Algorithms are held in a registry keyed by the token's `alg` header, so an
// algorithm with no registered verifier has no code path that reaches
// signature verification at all. A host needing asymmetric auth registers its
// own verifier backed by its own crypto library via register_verifier(); this
// project deliberately does not hand-roll curve arithmetic.

class SimpleJWTValidator {
public:
    struct JWTClaim {
        std::string sub;        // Subject (agent ID)
        std::string scope;      // Scope (e.g., "read:src/auth.ts", "write:tests/")
        std::string iss;
        std::string aud;
        int64_t exp;            // Expiration timestamp (Unix epoch)
        bool valid = false;
    };

    // Verifies `signature` (raw decoded bytes) over `signing_input`
    // ("<header_b64>.<payload_b64>"). Returns true only on a valid signature.
    using Verifier = std::function<bool(const std::string& signing_input,
                                        const std::string& signature)>;

    // Register a verifier for an `alg` header value. Registering an algorithm
    // is the ONLY way to make tokens carrying it verifiable.
    void register_verifier(const std::string& alg, Verifier verifier) {
        verifiers_[alg] = std::move(verifier);
    }

    // Initialize validator with a shared secret key for HMAC-SHA256
    SimpleJWTValidator(const std::string& shared_secret = "",
                       bool insecure_test_mode = false,
                       const std::string& expected_iss = "",
                       const std::string& expected_aud = "")
        : expected_iss_(expected_iss), expected_aud_(expected_aud) {
        if (!shared_secret.empty()) {
            shared_secret_ = shared_secret;
        } else {
            const char* env_secret = std::getenv("LLM_TOP_JWT_SECRET");
            if (env_secret && std::strlen(env_secret) > 0) {
                shared_secret_ = env_secret;
            } else if (insecure_test_mode) {
                shared_secret_ = "llm-top-test-secret-key-2026";
            } else {
                throw std::runtime_error("Empty JWT secret key. Enforce security by setting LLM_TOP_JWT_SECRET environment variable.");
            }
        }

        // The one algorithm shipped in-tree.
        verifiers_["HS256"] = [this](const std::string& signing_input,
                                     const std::string& signature) {
            if (signature.size() != SHA256::DIGEST_SIZE) return false;
            auto expected = HMAC_SHA256::compute(shared_secret_, signing_input);
            std::array<uint8_t, SHA256::DIGEST_SIZE> received;
            std::memcpy(received.data(), signature.data(), SHA256::DIGEST_SIZE);
            return HMAC_SHA256::verify(expected, received);
        };
    }

    // Create a signed JWT token for testing and internal use
    std::string create_token(const std::string& sub, const std::string& scope, int64_t exp,
                             const std::string& iss = "", const std::string& aud = "") {
        std::string header = base64url_encode("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        // Escape all string claims so a crafted value cannot inject additional JSON keys.
        std::string payload_json = "{\"sub\":\"" + escape_json(sub) + "\",\"scope\":\"" +
                                   escape_json(scope) + "\",\"exp\":" + std::to_string(exp);
        if (!iss.empty()) {
            payload_json += ",\"iss\":\"" + escape_json(iss) + "\"";
        }
        if (!aud.empty()) {
            payload_json += ",\"aud\":\"" + escape_json(aud) + "\"";
        }
        payload_json += "}";
        std::string payload = base64url_encode(payload_json);
        std::string signing_input = header + "." + payload;
        
        auto sig_bytes = HMAC_SHA256::compute(shared_secret_, signing_input);
        std::string signature = base64url_encode(
            std::string(reinterpret_cast<const char*>(sig_bytes.data()), sig_bytes.size()));
        
        return signing_input + "." + signature;
    }

    // Verify JWT structure, signature, and extract claims
    // Format: <header>.<payload>.<signature> (all base64url-encoded)
    JWTClaim verify(const std::string& token, const std::string& expected_scope = "") {
        JWTClaim claim;
        
        // Split into 3 parts
        size_t dot1 = token.find('.');
        if (dot1 == std::string::npos) return claim;
        
        size_t dot2 = token.find('.', dot1 + 1);
        if (dot2 == std::string::npos) return claim;
        
        // Reject if more than 2 dots
        if (token.find('.', dot2 + 1) != std::string::npos) return claim;

        std::string header_b64 = token.substr(0, dot1);
        std::string payload_b64 = token.substr(dot1 + 1, dot2 - dot1 - 1);
        std::string signature_b64 = token.substr(dot2 + 1);

        if (signature_b64.empty()) return claim;

        // Step 1: the alg header selects the verifier. An algorithm with no
        // registered verifier is rejected here, so there is no path by which a
        // token's claimed alg can differ from the algorithm actually used to
        // check it. ("none" and every unregistered alg fall out here.)
        std::string decoded_header = base64url_decode(header_b64);
        std::string alg = extract_string_claim(decoded_header, "alg");
        auto verifier_it = verifiers_.find(alg);
        if (verifier_it == verifiers_.end()) {
            return claim;
        }

        // Step 2: Verify the signature with that algorithm's verifier.
        std::string signing_input = header_b64 + "." + payload_b64;
        std::string decoded_sig = base64url_decode(signature_b64);
        if (!verifier_it->second(signing_input, decoded_sig)) {
            return claim;
        }

        // Step 3: Decode and parse payload
        std::string decoded_payload = base64url_decode(payload_b64);
        
        // Extract claims from JSON (simplified parser — handles our known format)
        claim.sub = extract_string_claim(decoded_payload, "sub");
        claim.scope = extract_string_claim(decoded_payload, "scope");
        claim.iss = extract_string_claim(decoded_payload, "iss");
        claim.aud = extract_string_claim(decoded_payload, "aud");
        claim.exp = extract_int_claim(decoded_payload, "exp");

        // Step 4: Check expiration
        int64_t current_time = get_unix_timestamp();
        if (claim.exp < current_time) {
            return claim; // Expired
        }

        // Step 5: Check iss and aud if configured
        if (!expected_iss_.empty() && claim.iss != expected_iss_) {
            return claim;
        }
        if (!expected_aud_.empty() && claim.aud != expected_aud_) {
            return claim;
        }

        // Step 6: Check scope matches (if requested)
        if (!expected_scope.empty() && claim.scope != expected_scope) {
            if (!scope_matches(claim.scope, expected_scope)) {
                return claim;
            }
        }

        claim.valid = true;
        return claim;
    }

    // Expose for testing
    static std::string base64url_encode(const std::string& input) {
        static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        std::string result;
        result.reserve((input.size() + 2) / 3 * 4);
        
        size_t len = input.size();
        
        for (size_t i = 0; i < len; i += 3) {
            uint32_t n = static_cast<uint32_t>(static_cast<uint8_t>(input[i])) << 16;
            
            if (i + 1 < len) n |= static_cast<uint32_t>(static_cast<uint8_t>(input[i + 1])) << 8;
            if (i + 2 < len) n |= static_cast<uint32_t>(static_cast<uint8_t>(input[i + 2]));
            
            result += table[(n >> 18) & 0x3F];
            result += table[(n >> 12) & 0x3F];
            if (i + 1 < len) result += table[(n >> 6) & 0x3F];
            if (i + 2 < len) result += table[n & 0x3F];
        }
        
        return result; // No padding — base64url omits '=' padding per RFC 7515
    }

    static std::string base64url_decode(const std::string& input) {
        static const uint8_t decode_table[256] = {
            // Initialize with 0xFF for invalid, then set valid chars
            255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
            255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
            255,255,255,255,255,255,255,255,255,255,255,255,255,62,255,255, // '-' = 62
            52,53,54,55,56,57,58,59,60,61,255,255,255,255,255,255,         // 0-9 = 52-61
            255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,            // A-O
            15,16,17,18,19,20,21,22,23,24,25,255,255,255,255,63,           // P-Z, '_' = 63
            255,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,             // a-o
            41,42,43,44,45,46,47,48,49,50,51,255,255,255,255,255,          // p-z
            255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
            255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
            255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
            255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
            255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
            255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
            255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
            255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255
        };
        
        std::string result;
        
        // Add padding for processing
        std::string padded = input;
        while (padded.size() % 4 != 0) padded += '=';
        
        result.reserve(padded.size() / 4 * 3);
        
        for (size_t i = 0; i + 3 < padded.size(); i += 4) {
            uint8_t a = decode_table[static_cast<uint8_t>(padded[i])];
            uint8_t b = decode_table[static_cast<uint8_t>(padded[i + 1])];
            uint8_t c = decode_table[static_cast<uint8_t>(padded[i + 2])];
            uint8_t d = decode_table[static_cast<uint8_t>(padded[i + 3])];
            
            if (a == 255 || b == 255) return ""; // Invalid
            
            uint32_t n = (static_cast<uint32_t>(a) << 18) |
                         (static_cast<uint32_t>(b) << 12);
            
            result += static_cast<char>((n >> 16) & 0xFF);
            
            if (padded[i + 2] != '=') {
                if (c == 255) return "";
                n |= static_cast<uint32_t>(c) << 6;
                result += static_cast<char>((n >> 8) & 0xFF);
            }
            
            if (padded[i + 3] != '=') {
                if (d == 255) return "";
                n |= static_cast<uint32_t>(d);
                result += static_cast<char>(n & 0xFF);
            }
        }
        
        return result;
    }

public:
    static std::string normalize_path_segment(const std::string& path_str) {
        if (path_str.empty()) return "";
        std::string s = path_str;
        for (char& c : s) { if (c == '\\') c = '/'; }

        std::vector<std::string> segments;
        size_t start = 0;
        while (start < s.length()) {
            size_t end = s.find('/', start);
            if (end == std::string::npos) end = s.length();
            std::string seg = s.substr(start, end - start);
            start = end + 1;
            if (seg.empty() || seg == ".") continue;
            if (seg == "..") {
                if (!segments.empty() && segments.back() != "..") {
                    segments.pop_back();
                } else {
                    segments.push_back(seg);
                }
            } else {
                segments.push_back(seg);
            }
        }
        std::string res;
        if (!s.empty() && s[0] == '/') res = "/";
        for (size_t i = 0; i < segments.size(); ++i) {
            if (i > 0) res += "/";
            res += segments[i];
        }
        return res;
    }

    static std::vector<std::string_view> split_scope_sv(std::string_view s, char delim) {
        std::vector<std::string_view> result;
        size_t start = 0;
        while (start < s.length()) {
            size_t end = s.find(delim, start);
            if (end == std::string_view::npos) end = s.length();
            result.push_back(s.substr(start, end - start));
            start = end + 1;
        }
        return result;
    }

    // Match one path segment against a pattern segment. A '*' inside a segment
    // is a wildcard for part of that segment only — it can never span a '/',
    // because callers only ever hand this a single already-split segment.
    static bool segment_matches(std::string_view pattern, std::string_view segment) {
        size_t star = pattern.find('*');
        if (star == std::string_view::npos) return pattern == segment;
        std::string_view prefix = pattern.substr(0, star);
        std::string_view suffix = pattern.substr(star + 1);
        if (segment.size() < prefix.size() + suffix.size()) return false;
        if (segment.compare(0, prefix.size(), prefix) != 0) return false;
        if (suffix.empty()) return true;
        return segment.compare(segment.size() - suffix.size(), suffix.size(), suffix) == 0;
    }

    // A path deeper than this is refused rather than truncated. Silently
    // dropping segments in an authorization decision would be a way to make a
    // long path match a short grant.
    static constexpr size_t kMaxPathSegments = 64;
    static constexpr size_t kTooManySegments = SIZE_MAX;

    // Split `s` on '/' or '\' while normalizing in place: empty segments and "."
    // are dropped and ".." pops the previous segment. Results are views into `s`,
    // so nothing is copied.
    //
    // This replaces normalize_path_segment()'s build-a-vector-of-strings-then-
    // join-them approach on the authorization path, which allocated a vector and
    // two strings for every scope segment of every request.
    static size_t normalize_segments(std::string_view s, std::string_view* out,
                                     size_t cap, bool* absolute) {
        *absolute = (!s.empty() && (s[0] == '/' || s[0] == '\\'));
        size_t count = 0, start = 0;
        while (start < s.size()) {
            size_t end = s.find_first_of("/\\", start);
            if (end == std::string_view::npos) end = s.size();
            std::string_view seg = s.substr(start, end - start);
            if (!seg.empty() && seg != ".") {
                if (seg == ".." && count > 0 && out[count - 1] != "..") {
                    --count;                       // climb back out
                } else {
                    if (count >= cap) return kTooManySegments;
                    out[count++] = seg;
                }
            }
            if (end == s.size()) break;
            start = end + 1;
        }
        return count;
    }

    // Match a slash-delimited path against a pattern, both already normalized
    // into segment arrays.
    //   '*'  matches exactly one path segment and never crosses '/'
    //   '**' matches all remaining segments
    // A traversal that climbs out of the granted subtree presents as a leading
    // ".." segment and fails to match.
    static bool path_glob_matches_segs(const std::string_view* p, size_t pn, bool p_abs,
                                       const std::string_view* t, size_t tn, bool t_abs) {
        if (p_abs != t_abs) return false;
        size_t i = 0;
        for (; i < pn; ++i) {
            if (p[i] == "**") return true;   // absorbs every remaining segment
            if (i >= tn) return false;
            if (p[i] == "*") continue;       // exactly one segment
            if (!segment_matches(p[i], t[i])) return false;
        }
        return i == tn;                      // no unmatched trailing segments
    }

    // Yield the next ':'-delimited segment of `s`, advancing `cursor`.
    // Returns false when exhausted. A trailing ':' yields no final empty
    // segment, matching the previous split behavior exactly.
    static bool next_colon_segment(std::string_view s, size_t& cursor, std::string_view& out) {
        if (cursor >= s.size()) return false;
        size_t end = s.find(':', cursor);
        if (end == std::string_view::npos) end = s.size();
        out = s.substr(cursor, end - cursor);
        cursor = end + 1;
        return true;
    }

    // Check if a granted scope authorizes a requested one. Scopes are split on
    // ':' into action/resource segments; the resource segment is then matched
    // as a path so that '*' cannot silently span directories.
    //
    // Allocation-free: both scopes are walked as views and path segments land in
    // stack buffers. This is the authorization hot path -- it runs for every
    // pointer and every tool call of every request.
    static bool scope_matches(std::string_view granted, std::string_view requested) {
        if (granted == "**") return true;

        size_t gc = 0, rc = 0, g_count = 0, r_count = 0;
        std::string_view g_seg, r_seg;

        while (next_colon_segment(granted, gc, g_seg)) {
            ++g_count;
            if (g_seg == "**") return true;     // grants everything from here on
            if (!next_colon_segment(requested, rc, r_seg)) return false;
            ++r_count;
            if (g_seg == "*") continue;         // any one colon-segment

            std::string_view gp[kMaxPathSegments], tp[kMaxPathSegments];
            bool g_abs = false, t_abs = false;
            size_t gn = normalize_segments(g_seg, gp, kMaxPathSegments, &g_abs);
            size_t tn = normalize_segments(r_seg, tp, kMaxPathSegments, &t_abs);
            if (gn == kTooManySegments || tn == kTooManySegments) return false;

            if (!path_glob_matches_segs(gp, gn, g_abs, tp, tn, t_abs)) return false;
        }

        while (next_colon_segment(requested, rc, r_seg)) ++r_count;
        return g_count == r_count;
    }

private:
    std::string shared_secret_;
    std::string expected_iss_;
    std::string expected_aud_;
    std::unordered_map<std::string, Verifier> verifiers_;

    // Return the raw JSON text of a key's value from the TOP-LEVEL object only.
    //
    // The previous implementation searched for "\"<key>\":\"" anywhere in the
    // payload, so the first textual match won -- including one inside a nested
    // object. A standards-conformant issuer that nests per-client scopes (a
    // Keycloak-style "realm_access": {"scope": ...}) could therefore override
    // the real top-level claim. This walks the object properly, skipping over
    // nested objects, arrays and strings.
    static std::string top_level_raw(const std::string& json, const std::string& key) {
        size_t i = 0, n = json.size();
        while (i < n && json[i] != '{') ++i;
        if (i == n) return "";
        ++i;

        auto skip_ws = [&]() {
            while (i < n && std::isspace(static_cast<unsigned char>(json[i]))) ++i;
        };

        while (i < n) {
            while (i < n && (std::isspace(static_cast<unsigned char>(json[i])) || json[i] == ',')) ++i;
            if (i >= n || json[i] == '}') break;
            if (json[i] != '"') break;  // malformed: keys must be strings

            // Key
            std::string k;
            ++i;
            bool esc = false;
            for (; i < n; ++i) {
                char c = json[i];
                if (esc)            { k += c; esc = false; }
                else if (c == '\\') { esc = true; }
                else if (c == '"')  { ++i; break; }
                else                { k += c; }
            }

            skip_ws();
            if (i >= n || json[i] != ':') break;
            ++i;
            skip_ws();

            // Value
            size_t vstart = i;
            if (i < n && json[i] == '"') {
                ++i; esc = false;
                for (; i < n; ++i) {
                    char c = json[i];
                    if (esc)            esc = false;
                    else if (c == '\\') esc = true;
                    else if (c == '"')  { ++i; break; }
                }
            } else if (i < n && (json[i] == '{' || json[i] == '[')) {
                int depth = 0;
                bool in_string = false;
                esc = false;
                for (; i < n; ++i) {
                    char c = json[i];
                    if (in_string) {
                        if (esc)            esc = false;
                        else if (c == '\\') esc = true;
                        else if (c == '"')  in_string = false;
                    } else if (c == '"')           { in_string = true; }
                    else if (c == '{' || c == '[') { ++depth; }
                    else if (c == '}' || c == ']') { if (--depth == 0) { ++i; break; } }
                }
            } else {
                while (i < n && json[i] != ',' && json[i] != '}') ++i;
            }

            if (k == key) return json.substr(vstart, i - vstart);
        }
        return "";
    }

    // Extract a top-level string claim, unescaping the JSON string body.
    static std::string extract_string_claim(const std::string& json, const std::string& key) {
        std::string raw = top_level_raw(json, key);
        if (raw.size() < 2 || raw.front() != '"' || raw.back() != '"') return "";
        std::string val;
        bool esc = false;
        for (size_t i = 1; i + 1 < raw.size(); ++i) {
            char c = raw[i];
            if (esc)            { val += c; esc = false; }
            else if (c == '\\') { esc = true; }
            else                { val += c; }
        }
        return val;
    }

    // Extract a top-level integer claim.
    static int64_t extract_int_claim(const std::string& json, const std::string& key) {
        std::string raw = top_level_raw(json, key);
        try {
            return std::stoll(raw);
        } catch (...) {
            return 0;
        }
    }
};

class IdempotencyStore {
public:
    enum class RecordResult {
        Recorded,          // first time this (agent, reqid) has been seen
        Replay,            // already executed within the TTL
        CapacityExceeded   // store is full of live guards; caller must fail closed
    };

    explicit IdempotencyStore(size_t max_entries = 1000, int64_t ttl_seconds = 3600)
        : max_entries_(max_entries), ttl_seconds_(ttl_seconds) {}

    // Record a request ID for an agent, after the request has been authorized.
    //
    // Entries expire by time rather than only by LRU pressure. When the store
    // is full of entries that have NOT expired, this reports CapacityExceeded
    // instead of evicting one: silently dropping a guard would let an attacker
    // reopen a replay window simply by flooding the store with fresh requests.
    RecordResult record_request(const std::string& agent_id, const std::string& reqid,
                                const std::string& checksum) {
        std::lock_guard<std::mutex> lock(mutex_);
        prune_expired();

        std::string key = agent_id + ":" + reqid;
        if (seen_requests_.find(key) != seen_requests_.end()) {
            return RecordResult::Replay;
        }
        if (seen_requests_.size() >= max_entries_) {
            return RecordResult::CapacityExceeded;
        }

        const int64_t now = get_unix_timestamp();
        seen_requests_[key] = Entry{checksum, now};
        history_.push_back(HistoryItem{key, now});
        return RecordResult::Recorded;
    }

    bool is_replayed(const std::string& agent_id, const std::string& reqid) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = seen_requests_.find(agent_id + ":" + reqid);
        if (it == seen_requests_.end()) return false;
        return !is_expired(it->second.recorded_at);
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        seen_requests_.clear();
        history_.clear();
    }

private:
    struct Entry {
        std::string checksum;
        int64_t recorded_at;
    };
    struct HistoryItem {
        std::string key;
        int64_t recorded_at;
    };

    bool is_expired(int64_t recorded_at) const {
        return get_unix_timestamp() - recorded_at >= ttl_seconds_;
    }

    // history_ is chronological, so expired entries are always at the front.
    void prune_expired() {
        while (!history_.empty() && is_expired(history_.front().recorded_at)) {
            auto it = seen_requests_.find(history_.front().key);
            // Only erase if the map entry is the one this history item recorded.
            if (it != seen_requests_.end() && it->second.recorded_at == history_.front().recorded_at) {
                seen_requests_.erase(it);
            }
            history_.pop_front();
        }
    }

    size_t max_entries_;
    int64_t ttl_seconds_;
    std::unordered_map<std::string, Entry> seen_requests_;
    std::deque<HistoryItem> history_;
    mutable std::mutex mutex_;
};


class LLMTOPMiddleware {
public:
    // A pointer field (e.g. tgt) that was authorized, with its resource path
    // already normalized.
    struct ApprovedPointer {
        std::string key;        // the statement key, e.g. "tgt"
        std::string resource;   // normalized path that was actually authorized
    };

    // A tool call that was authorized. `args` carries the resource argument
    // rewritten to its normalized form, so a host executing this plan cannot
    // accidentally act on the raw, un-normalized string the model emitted.
    struct ApprovedTool {
        std::string name;
        ordered_map args;
        std::string resource;   // normalized; empty when the call takes no resource
        std::optional<std::string> method;
    };

    struct ExecutionPlan {
        bool authorized = false;
        // Human-readable trail, kept for logging.
        std::vector<std::string> approved_actions;
        // Machine-consumable decisions. A host should execute THESE, not
        // re-derive paths from the AST: what was authorized and what gets
        // executed must be the same string.
        std::vector<ApprovedPointer> approved_pointers;
        std::vector<ApprovedTool> approved_tools;
        std::string error_message;
    };

    // Initialize with optional JWT validator and delegation option
    LLMTOPMiddleware(std::shared_ptr<SimpleJWTValidator> jwt_validator = nullptr, bool allow_delegation = false)
        : jwt_validator_(jwt_validator ? jwt_validator : std::make_shared<SimpleJWTValidator>()),
          allow_delegation_(allow_delegation) {}

    // Enable or disable host out-of-band proxy mode (where capabilities are host-managed by session ID/agent)
    void set_out_of_band_proxy(bool enable) {
        out_of_band_proxy_mode_ = enable;
    }

    bool out_of_band_proxy_enabled() const {
        return out_of_band_proxy_mode_;
    }

    void grant_session_capability(const std::string& agent_id, const std::string& scope) {
        std::lock_guard<std::mutex> lock(session_mutex_);
        session_granted_scopes_[agent_id].push_back(scope);
    }

    void revoke_session_capabilities(const std::string& agent_id) {
        std::lock_guard<std::mutex> lock(session_mutex_);
        session_granted_scopes_.erase(agent_id);
    }

    // Enable or disable CHK integrity verification. On by default.
    //
    // CHK is an unkeyed digest, so it detects accidents (truncation, a mangled
    // copy) and not attackers, who simply recompute it. That makes it valuable
    // exactly where a frame crosses a boundary both sides compute over -- a
    // gateway on one host, an enforcement service on another.
    //
    // Turn it off when the producer and the verifier are the same process. There
    // the frame never crossed anything, so stamping it with stamp_chk() and then
    // verifying it here checks a hash against memory that was never at risk. It
    // costs a SHA-256 over every frame to learn nothing.
    //
    // Note an LLM cannot compute SHA-256 over its own output, so a frame taken
    // straight from a model never carries a valid CHK. Either stamp it at ingest
    // with stamp_chk() (see chk.hpp) or turn this off for that leg.
    void set_verify_chk(bool enable) {
        verify_chk_ = enable;
    }

    bool verify_chk_enabled() const {
        return verify_chk_;
    }

    // Enable or disable idempotency enforcement (replay protection)
    void set_enforce_idempotency(bool enable) {
        enforce_idempotency_ = enable;
    }

    bool enforce_idempotency_enabled() const {
        return enforce_idempotency_;
    }

    void clear_idempotency_store() {
        idempotency_store_.clear();
    }

    ExecutionPlan evaluate(const AST& ast, bool accept_healed = false) {
        ExecutionPlan plan;

        // 1. Verify Request Header Integrity
        if (ast.header.agt.empty() || ast.header.reqid.empty()) {
            plan.error_message = "ERR:auth_rejected - Missing agent or request ID";
            return plan;
        }

        // Refuse healed statements unless explicitly opted in
        if (!ast.healed_draft.empty() && !accept_healed) {
            plan.error_message = "ERR:auth_rejected - Healed statements present but not accepted";
            return plan;
        }

        // 1b. Verify payload integrity: CHK must equal sha256 of the canonical
        // frame. Producers stamp this with stamp_chk() (chk.hpp); see
        // set_verify_chk() for when this check is worth paying for at all.
        if (verify_chk_) {
            std::string computed_chk = compute_chk(ast.raw_frame);
            if (ast.header.chk != computed_chk) {
                plan.error_message = "ERR:integrity - checksum mismatch";
                return plan;
            }
        }

        // 1c. Replay protection: reject a REQID that has already been executed.
        // The REQID is only *recorded* once authorization has fully succeeded
        // (see the end of this function), so a request that fails the capability
        // checks does not burn the id for the legitimate retry.
        if (enforce_idempotency_ && idempotency_store_.is_replayed(ast.header.agt, ast.header.reqid)) {
            plan.error_message = "ERR:replay_detected - Request ID '" + ast.header.reqid + "' has already been executed for agent '" + ast.header.agt + "'";
            return plan;
        }

        std::vector<const std::vector<Statement>*> batches = { &ast.statements };
        if (accept_healed && !ast.healed_draft.empty()) {
            batches.push_back(&ast.healed_draft);
        }

        for (const auto* batch : batches) {
            for (const auto& stmt : *batch) {
                // 2. Default-deny: every pointer field MUST carry a valid capability (or host proxy grant).
                for (const auto& kv : stmt.kvpairs) {
                    if (!is_pointer_key(kv.first)) continue;

                    std::string resource =
                        SimpleJWTValidator::normalize_path_segment(extract_resource_path(kv.second));
                    if (escapes_root(resource)) {
                        plan.error_message = "ERR:cap_required - pointer field '" + kv.first +
                                             "' resolves outside any grantable root: " + resource;
                        return plan;
                    }
                    if (kv.second.find("cap=") != std::string::npos) {
                        // In-band JWT token present. Any `ttl=` alongside it is
                        // ignored; the token's signed `exp` governs expiry.
                        std::string cap_token = extract_capability_token(kv.second);

                        if (!validate_capability(cap_token, resource, ast.header.agt)) {
                            plan.error_message = "ERR:cap_invalid_or_expired for target: " + kv.first;
                            return plan;
                        }
                        plan.approved_actions.push_back("READ/WRITE authorized for " + resource);
                        plan.approved_pointers.push_back(ApprovedPointer{kv.first, resource});
                    } else if (out_of_band_proxy_mode_) {
                        // Out-of-band proxy mode: check host session capability grant
                        if (!validate_proxy_capability(ast.header.agt, "read:" + resource) &&
                            !validate_proxy_capability(ast.header.agt, "write:" + resource) &&
                            !validate_proxy_capability(ast.header.agt, resource)) {
                            plan.error_message = "ERR:cap_required - target '" + kv.first + "' (" + resource +
                                                 ") not authorized for agent '" + ast.header.agt + "' in proxy session";
                            return plan;
                        }
                        plan.approved_actions.push_back("READ/WRITE authorized (out-of-band proxy) for " + resource);
                        plan.approved_pointers.push_back(ApprovedPointer{kv.first, resource});
                    } else {
                        plan.error_message = "ERR:cap_required - pointer field '" + kv.first +
                                             "' has no capability token";
                        return plan;
                    }
                }

                // 3. Default-deny: every tool call MUST carry a valid capability (or host proxy grant).
                for (const auto& tool : stmt.tool_calls) {
                    std::string scope = "execute:" + tool.name;
                    auto [resource_key, raw_resource] = tool_resource(tool.args);
                    std::string resource =
                        SimpleJWTValidator::normalize_path_segment(raw_resource);
                    if (escapes_root(resource)) {
                        plan.error_message = "ERR:exec - tool call '" + tool.name +
                                             "' resolves outside any grantable root: " + resource;
                        return plan;
                    }
                    if (!resource.empty()) scope += ":" + resource;

                    // Built here, recorded only on an authorized branch below.
                    // The normalized resource is written back into the argument
                    // map so what the host executes is exactly what was
                    // authorized, not the raw string the model emitted.
                    ApprovedTool approved;
                    approved.name = tool.name;
                    approved.args = tool.args;
                    approved.resource = resource;
                    approved.method = tool.method;
                    if (!resource_key.empty()) approved.args[resource_key] = resource;

                    auto cap_it = tool.args.find("cap");
                    if (cap_it != tool.args.end()) {
                        // In-band JWT token present. Any `ttl=` argument is
                        // ignored; the token's signed `exp` governs expiry.
                        std::string cap_token = cap_it->second;

                        if (!validate_capability(cap_token, scope, ast.header.agt)) {
                            plan.error_message = "ERR:exec - Unauthorized tool call: " + tool.name;
                            return plan;
                        }
                        plan.approved_actions.push_back("TOOL authorized: " + tool.name);
                        plan.approved_tools.push_back(approved);
                    } else if (out_of_band_proxy_mode_) {
                        // Out-of-band proxy mode: check host session capability grant
                        if (!validate_proxy_capability(ast.header.agt, scope)) {
                            plan.error_message = "ERR:exec - Unauthorized tool call: " + tool.name +
                                                 " for agent " + ast.header.agt + " in proxy session";
                            return plan;
                        }
                        plan.approved_actions.push_back("TOOL authorized (out-of-band proxy): " + tool.name);
                        plan.approved_tools.push_back(approved);
                    } else {
                        plan.error_message = "ERR:exec - missing capability for tool call: " + tool.name;
                        return plan;
                    }
                }
            }
        }

        // Everything is authorized. Consume the REQID now, not earlier. Doing
        // this last also closes the race between the is_replayed() check above
        // and this point: whichever concurrent caller records first wins, and
        // the loser is rejected here rather than both being authorized.
        if (enforce_idempotency_) {
            switch (idempotency_store_.record_request(ast.header.agt, ast.header.reqid, ast.header.chk)) {
                case IdempotencyStore::RecordResult::Recorded:
                    break;
                case IdempotencyStore::RecordResult::Replay:
                    plan.approved_actions.clear();
                    plan.error_message = "ERR:replay_detected - Request ID '" + ast.header.reqid +
                                         "' has already been executed for agent '" + ast.header.agt + "'";
                    return plan;
                case IdempotencyStore::RecordResult::CapacityExceeded:
                    // Fail closed: without a free slot we cannot promise this
                    // request will not be replayed later.
                    plan.approved_actions.clear();
                    plan.error_message = "ERR:replay_detected - idempotency store at capacity; "
                                         "cannot guarantee exactly-once execution";
                    return plan;
            }
        }

        plan.authorized = true;
        return plan;
    }

private:
    std::shared_ptr<SimpleJWTValidator> jwt_validator_;
    bool allow_delegation_;
    // Atomic because evaluate() reads these while another thread may be
    // reconfiguring the middleware; the class advertises thread safety.
    std::atomic<bool> out_of_band_proxy_mode_{false};
    std::atomic<bool> enforce_idempotency_{false};
    std::atomic<bool> verify_chk_{true};
    IdempotencyStore idempotency_store_;
    std::unordered_map<std::string, std::vector<std::string>> session_granted_scopes_;
    mutable std::mutex session_mutex_;

    bool validate_proxy_capability(const std::string& agent_id, const std::string& requested_scope) {
        std::lock_guard<std::mutex> lock(session_mutex_);
        auto it = session_granted_scopes_.find(agent_id);
        if (it == session_granted_scopes_.end()) return false;
        for (const std::string& granted : it->second) {
            if (granted == requested_scope || SimpleJWTValidator::scope_matches(granted, requested_scope)) {
                return true;
            }
        }
        return false;
    }

    // Pointer fields reference a protected resource and therefore require a capability.
    // Kept as an explicit allow-list so it is easy to extend (matches schema is_pointer).
    static bool is_pointer_key(const std::string& key) {
        return key == "tgt";
    }

    // The resource a tool call operates on: first present of these argument names.
    // Bound into the capability scope so a token cannot be reused on a different
    // target. Returns the argument name as well so the caller can rewrite that
    // argument to the normalized path in the approved plan.
    static std::pair<std::string, std::string> tool_resource(const ordered_map& args) {
        for (const std::string& k : {std::string("path"), std::string("target"),
                                     std::string("file"), std::string("resource")}) {
            auto it = args.find(k);
            if (it != args.end()) return {k, it->second};
        }
        return {"", ""};
    }

    // A resource that normalizes to a path climbing above its own root escapes
    // whatever subtree a grant could describe, so it is refused outright rather
    // than left for scope matching to catch. Normalization alone canonicalizes;
    // it does not confine.
    static bool escapes_root(const std::string& normalized) {
        return normalized == ".." || normalized.rfind("../", 0) == 0;
    }

    // NOTE: the in-band `ttl=` field is deliberately NOT enforced.
    //
    // It travelled unsigned alongside the token, so anyone able to modify the
    // payload could extend or strip it at will -- and since CHK is unkeyed they
    // could recompute that too. Enforcing a value an attacker fully controls
    // provides no security while costing tokens on every pointer and tool call.
    // The JWT's signed `exp` claim is the sole authority on expiry.

    bool validate_capability(const std::string& cap_token, const std::string& resource, const std::string& agent_id) {
        auto claim = jwt_validator_->verify(cap_token, resource);
        
        if (!claim.valid) {
            return false;
        }

        // Verify agent_id matches claim subject unless delegation is allowed
        if (!allow_delegation_ && claim.sub != agent_id) {
            return false;
        }
        
        return true;
    }

    std::string extract_capability_token(const std::string& pointer_str) {
        size_t cap_pos = pointer_str.find("cap=");
        if (cap_pos == std::string::npos) return "";
        
        size_t start = cap_pos + 4;
        size_t end = pointer_str.find(';', start);
        if (end == std::string::npos) {
            end = pointer_str.length();
        }
        return pointer_str.substr(start, end - start);
    }

    std::string extract_resource_path(const std::string& pointer_str) {
        size_t colon = pointer_str.find(':');
        if (colon == std::string::npos) {
            return pointer_str;
        }
        return pointer_str.substr(0, colon);
    }
};
