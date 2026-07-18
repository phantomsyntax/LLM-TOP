#pragma once
#include "parser_v2.hpp"
#include <iostream>
#include <chrono>
#include <string>
#include <stdexcept>

// Mocking time for testing purposes (in reality, use system clock)
std::string get_current_iso_time() {
    return "2026-07-18T08:30:00Z";
}

class LLMTOPMiddleware {
public:
    struct ExecutionPlan {
        bool authorized = false;
        std::vector<std::string> approved_actions;
        std::string error_message;
    };

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
                if (kv.second.find("cap=") != std::string::npos) {
                    if (!validate_pointer(kv.second)) {
                        plan.error_message = "ERR:cap_invalid_or_expired for target: " + kv.first;
                        return plan;
                    }
                    plan.approved_actions.push_back("READ/WRITE authorized for " + kv.second);
                }
            }

            // 3. Scan Tool Calls for Capabilities
            for (const auto& tool : stmt.tool_calls) {
                if (tool.args.find("cap") != tool.args.end()) {
                    if (!verify_jwt_signature(tool.args.at("cap"))) {
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
    bool validate_pointer(const std::string& pointer_str) {
        // Example pointer_str: src/auth.ts:cap=XYZ123;ttl=2026-07-18T09:00:00Z
        size_t cap_pos = pointer_str.find("cap=");
        size_t ttl_pos = pointer_str.find("ttl=");
        
        if (cap_pos == std::string::npos) return false;

        std::string cap = pointer_str.substr(cap_pos + 4);
        size_t semicolon = cap.find(';');
        if (semicolon != std::string::npos) cap = cap.substr(0, semicolon);

        if (!verify_jwt_signature(cap)) return false;

        if (ttl_pos != std::string::npos) {
            std::string ttl = pointer_str.substr(ttl_pos + 4);
            // Lexicographical string compare works for standard ISO8601 UTC times
            if (ttl < get_current_iso_time()) {
                std::cerr << "DIAGNOSTIC: Token expired. TTL=" << ttl << " Current=" << get_current_iso_time() << "\n";
                return false; 
            }
        }

        return true;
    }

    bool verify_jwt_signature(const std::string& token) {
        // In production, cryptographically verify the signature against a public key.
        // For testing, we accept any token starting with "VALID_"
        return (token.rfind("VALID_", 0) == 0); 
    }
};
