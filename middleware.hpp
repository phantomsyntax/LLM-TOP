#pragma once
#include "parser_v2.hpp"
#include "sha256.hpp"
#include "time_utils.hpp"
#include <iostream>
#include <chrono>
#include <string>
#include <stdexcept>
#include <unordered_map>
#include <memory>
#include <array>
#include <vector>
#include <sstream>

// Real JWT validator for capability tokens using HMAC-SHA256.
// Implements proper base64url encoding/decoding, signature verification,
// and claim extraction per RFC 7519.
// For production at scale, replace HMAC-SHA256 with RS256/EdDSA via OpenSSL.

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
    }

    // Create a signed JWT token for testing and internal use
    std::string create_token(const std::string& sub, const std::string& scope, int64_t exp,
                             const std::string& iss = "", const std::string& aud = "") {
        std::string header = base64url_encode("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        std::string payload_json = "{\"sub\":\"" + sub + "\",\"scope\":\"" + scope + "\",\"exp\":" + std::to_string(exp);
        if (!iss.empty()) {
            payload_json += ",\"iss\":\"" + iss + "\"";
        }
        if (!aud.empty()) {
            payload_json += ",\"aud\":\"" + aud + "\"";
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

        // Step 1: Decode header and verify alg is exactly HS256
        std::string decoded_header = base64url_decode(header_b64);
        std::string alg = extract_string_claim(decoded_header, "alg");
        if (alg != "HS256") {
            return claim; // Reject none and other algs
        }

        // Step 2: Verify HMAC-SHA256 signature
        std::string signing_input = header_b64 + "." + payload_b64;
        auto expected_sig = HMAC_SHA256::compute(shared_secret_, signing_input);
        
        std::string decoded_sig = base64url_decode(signature_b64);
        if (decoded_sig.size() != SHA256::DIGEST_SIZE) return claim;
        
        std::array<uint8_t, SHA256::DIGEST_SIZE> received_sig;
        std::memcpy(received_sig.data(), decoded_sig.data(), SHA256::DIGEST_SIZE);
        
        if (!HMAC_SHA256::verify(expected_sig, received_sig)) {
            // Signature mismatch — reject
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

private:
    std::string shared_secret_;
    std::string expected_iss_;
    std::string expected_aud_;

    static std::vector<std::string> split_scope(const std::string& s, char delim) {
        std::vector<std::string> result;
        std::stringstream ss(s);
        std::string item;
        while (std::getline(ss, item, delim)) {
            result.push_back(item);
        }
        return result;
    }

    // Check if scope pattern matches requested resource (split on :, * matches one segment)
    bool scope_matches(const std::string& granted, const std::string& requested) {
        auto g_segs = split_scope(granted, ':');
        auto r_segs = split_scope(requested, ':');
        if (g_segs.size() != r_segs.size()) return false;
        for (size_t i = 0; i < g_segs.size(); ++i) {
            if (g_segs[i] == "*") continue;
            if (g_segs[i].find('*') != std::string::npos) {
                std::string pattern = g_segs[i].substr(0, g_segs[i].find('*'));
                if (r_segs[i].substr(0, pattern.length()) != pattern) {
                    return false;
                }
            } else if (g_segs[i] != r_segs[i]) {
                return false;
            }
        }
        return true;
    }

    // Extract a string claim value from simplified JSON
    std::string extract_string_claim(const std::string& json, const std::string& key) {
        std::string search = "\"" + key + "\":\"";
        size_t pos = json.find(search);
        if (pos == std::string::npos) return "";
        size_t start = pos + search.length();
        size_t end = json.find('"', start);
        if (end == std::string::npos) return "";
        return json.substr(start, end - start);
    }

    // Extract an integer claim value from simplified JSON
    int64_t extract_int_claim(const std::string& json, const std::string& key) {
        std::string search = "\"" + key + "\":";
        size_t pos = json.find(search);
        if (pos == std::string::npos) return 0;
        size_t start = pos + search.length();
        size_t end = json.find_first_not_of("0123456789", start);
        if (end == std::string::npos) end = json.length();
        try {
            return std::stoll(json.substr(start, end - start));
        } catch (...) {
            return 0;
        }
    }
};


class LLMTOPMiddleware {
public:
    struct ExecutionPlan {
        bool authorized = false;
        std::vector<std::string> approved_actions;
        std::string error_message;
    };

    // Initialize with optional JWT validator and delegation option
    LLMTOPMiddleware(std::shared_ptr<SimpleJWTValidator> jwt_validator = nullptr, bool allow_delegation = false)
        : jwt_validator_(jwt_validator ? jwt_validator : std::make_shared<SimpleJWTValidator>()),
          allow_delegation_(allow_delegation) {}

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

        std::vector<const std::vector<Statement>*> batches = { &ast.statements };
        if (accept_healed && !ast.healed_draft.empty()) {
            batches.push_back(&ast.healed_draft);
        }

        for (const auto* batch : batches) {
            for (const auto& stmt : *batch) {
                // 2. Scan and Validate all Capabilities in KV pairs
                for (const auto& kv : stmt.kvpairs) {
                    // Look for cap= patterns in pointers
                    if (kv.second.find("cap=") != std::string::npos) {
                        std::string cap_token = extract_capability_token(kv.second);
                        std::string resource = extract_resource_path(kv.second);
                        
                        if (!validate_capability(cap_token, resource, ast.header.agt)) {
                            plan.error_message = "ERR:cap_invalid_or_expired for target: " + kv.first;
                            return plan;
                        }
                        plan.approved_actions.push_back("READ/WRITE authorized for " + resource);
                    }
                }

                // 3. Scan Tool Calls for Capabilities
                for (const auto& tool : stmt.tool_calls) {
                    if (tool.args.find("cap") != tool.args.end()) {
                        std::string cap_token = tool.args.at("cap");
                        std::string scope = "execute:" + tool.name;
                        
                        if (!validate_capability(cap_token, scope, ast.header.agt)) {
                            plan.error_message = "ERR:exec - Unauthorized tool call: " + tool.name;
                            return plan;
                        }
                        plan.approved_actions.push_back("TOOL authorized: " + tool.name);
                    }
                }
            }
        }

        plan.authorized = true;
        return plan;
    }

private:
    std::shared_ptr<SimpleJWTValidator> jwt_validator_;
    bool allow_delegation_;

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
