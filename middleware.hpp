#pragma once
#include "parser_v2.hpp"
#include <iostream>
#include <chrono>
#include <string>
#include <stdexcept>
#include <unordered_map>
#include <memory>
#include <ctime>
#include <iomanip>
#include <sstream>

// Simple JWT validator for capability tokens
// In production, use libsodium or OpenSSL for cryptographic rigor
class SimpleJWTValidator {
public:
    struct JWTClaim {
        std::string sub;        // Subject (agent ID)
        std::string scope;      // Scope (e.g., "read:src/auth.ts", "write:tests/")
        int64_t exp;            // Expiration timestamp (Unix epoch)
        bool valid = false;
    };

    // Initialize validator with a shared secret key (in prod, use public key + HSM)
    SimpleJWTValidator(const std::string& shared_secret = "") 
        : shared_secret_(shared_secret) {}

    // Verify JWT structure and extract claims
    // Format: <header>.<payload>.<signature> where payload is base64url-encoded JSON
    JWTClaim verify(const std::string& token, const std::string& expected_scope = "") {
        JWTClaim claim;
        
        // Count dots - must be exactly 2 for valid JWT format
        size_t dot1 = token.find('.');
        size_t dot2 = token.find('.', dot1 + 1);
        
        if (dot1 == std::string::npos || dot2 == std::string::npos || 
            token.find('.', dot2 + 1) != std::string::npos) {
            // Invalid JWT structure
            return claim;
        }

        std::string header = token.substr(0, dot1);
        std::string payload = token.substr(dot1 + 1, dot2 - dot1 - 1);
        std::string signature = token.substr(dot2 + 1);

        // In a trusted environment, we validate:
        // 1. JWT structure is valid (3 parts separated by dots)
        // 2. Signature is present and non-empty
        // 3. Expiration is in the future
        // 4. Scope matches the requested resource
        
        if (signature.empty()) {
            return claim;
        }

        // Decode base64url payload (simplified - assumes valid base64url)
        std::string decoded_payload = base64url_decode(payload);
        
        // Parse JSON-like claims (simplified: no full JSON parser)
        // Expected format: {"sub":"agent-1","scope":"read:src/auth.ts","exp":1721305200}
        
        // Extract subject
        size_t sub_pos = decoded_payload.find("\"sub\":\"");
        if (sub_pos != std::string::npos) {
            size_t start = sub_pos + 8;
            size_t end = decoded_payload.find('"', start);
            if (end != std::string::npos) {
                claim.sub = decoded_payload.substr(start, end - start);
            }
        }
        
        // Extract scope
        size_t scope_pos = decoded_payload.find("\"scope\":\"");
        if (scope_pos != std::string::npos) {
            size_t start = scope_pos + 9;
            size_t end = decoded_payload.find('"', start);
            if (end != std::string::npos) {
                claim.scope = decoded_payload.substr(start, end - start);
            }
        }
        
        // Extract expiration
        size_t exp_pos = decoded_payload.find("\"exp\":");
        if (exp_pos != std::string::npos) {
            size_t start = exp_pos + 6;
            size_t end = decoded_payload.find_first_not_of("0123456789", start);
            if (end == std::string::npos) end = decoded_payload.length();
            try {
                claim.exp = std::stoll(decoded_payload.substr(start, end - start));
            } catch (...) {
                return claim;
            }
        }

        // Check expiration
        auto now = std::chrono::system_clock::now();
        int64_t current_time = std::chrono::system_clock::to_time_t(now);
        if (claim.exp < current_time) {
            // Token expired
            return claim;
        }

        // Check scope matches (if requested)
        if (!expected_scope.empty() && claim.scope != expected_scope) {
            // Scope mismatch - may allow partial matches for path hierarchies
            // e.g., "read:src/*" matches "read:src/auth.ts"
            if (!scope_matches(claim.scope, expected_scope)) {
                return claim;
            }
        }

        claim.valid = true;
        return claim;
    }

private:
    std::string shared_secret_;

    // Simplified base64url decoder (production: use a proper library)
    std::string base64url_decode(const std::string& encoded) {
        // In production, implement proper base64url decoding
        // For now, return as-is to show structure
        return encoded;
    }

    // Check if scope pattern matches requested resource
    bool scope_matches(const std::string& granted, const std::string& requested) {
        // Examples:
        // "read:src/*" grants "read:src/auth.ts"
        // "write:tests/" grants "write:tests/auth.test.ts"
        if (granted.find('*') != std::string::npos) {
            std::string pattern = granted.substr(0, granted.find('*'));
            return requested.substr(0, pattern.length()) == pattern;
        }
        return granted == requested;
    }
};

// Get current ISO 8601 time string
std::string get_current_iso_time() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::put_time(std::gmtime(&time), "%FT%TZ");
    return oss.str();
}

// Get current Unix timestamp
int64_t get_current_unix_time() {
    auto now = std::chrono::system_clock::now();
    return std::chrono::system_clock::to_time_t(now);
}

class LLMTOPMiddleware {
public:
    struct ExecutionPlan {
        bool authorized = false;
        std::vector<std::string> approved_actions;
        std::string error_message;
    };

    // Initialize with optional JWT validator (use in production)
    LLMTOPMiddleware(std::shared_ptr<SimpleJWTValidator> jwt_validator = nullptr)
        : jwt_validator_(jwt_validator ? jwt_validator : std::make_shared<SimpleJWTValidator>()) {}

    ExecutionPlan evaluate(const AST& ast) {
        ExecutionPlan plan;

        // 1. Verify Request Header Integrity
        if (ast.header.agt.empty() || ast.header.reqid.empty()) {
            plan.error_message = "ERR:auth_rejected - Missing agent or request ID";
            return plan;
        }

        // 2. Scan and Validate all Capabilities in KV pairs
        for (const auto& stmt : ast.statements) {
            for (const auto& kv : stmt.kvpairs) {
                // Look for cap= patterns in pointers
                // Format: file_path:cap=TOKEN;ttl=ISO8601
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

        plan.authorized = true;
        return plan;
    }

private:
    std::shared_ptr<SimpleJWTValidator> jwt_validator_;

    bool validate_capability(const std::string& cap_token, const std::string& resource, const std::string& agent_id) {
        // Extract TTL from token context if available
        auto claim = jwt_validator_->verify(cap_token, resource);
        
        if (!claim.valid) {
            return false;
        }

        // In trusted environment, if JWT validates, approve
        // In untrusted environment, add additional checks:
        // - Verify agent_id matches claim.sub
        // - Check resource hierarchy matches scope
        // - Log all access for audit
        
        return true;
    }

    std::string extract_capability_token(const std::string& pointer_str) {
        // Format: src/auth.ts:cap=TOKEN;ttl=ISO8601
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
        // Extract path before first ':'
        size_t colon = pointer_str.find(':');
        if (colon == std::string::npos) {
            return pointer_str;
        }
        return pointer_str.substr(0, colon);
    }
};
