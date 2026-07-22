#pragma once
#include "parser_v2.hpp"
#include "json_utils.hpp"
#include "time_utils.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <ctime>
#include <cctype>
#include <algorithm>

// Fallback Recovery System for LLM-TOP
// When a payload is corrupted or malformed, this system:
// 1. Detects errors in TOLERANT mode
// 2. Generates a recovery instruction for the Planner agent
// 3. Optionally re-parses with corrections
// 4. Logs the incident for audit trail

class FallbackRecoveryManager {
public:
    enum class RecoveryAction {
        REPARSE_SUGGESTED,      // Recovery instructions for Planner
        PARTIAL_SUCCESS,        // Some statements parsed, others failed
        COMPLETE_FAILURE,       // Unable to recover; fallback to JSON diagnostic
        NO_ERROR
    };

    struct RecoveryPlan {
        RecoveryAction action = RecoveryAction::NO_ERROR;
        std::string recovery_instruction;  // Message for Planner to fix
        std::string fallback_json;         // Fallback JSON structure
        int errors_found = 0;
        int statements_recovered = 0;
        int statements_total = 0;
        std::vector<std::string> error_details;
    };

    // Analyze an AST with diagnostics and generate recovery plan
    RecoveryPlan analyze_and_recover(const AST& ast, const std::string& original_payload = "") {
        RecoveryPlan plan;

        // Check if diagnostics were captured during parsing
        if (!ast.diagnostic.empty()) {
            plan.error_details.push_back(ast.diagnostic);
            // The parser joins individual diagnostics with " | "; count each one.
            plan.errors_found = 1;
            size_t pos = 0;
            while ((pos = ast.diagnostic.find(" | ", pos)) != std::string::npos) {
                plan.errors_found++;
                pos += 3;
            }
        }

        plan.statements_total = static_cast<int>(ast.statements.size());
        
        // Count successfully parsed statements
        for (const auto& stmt : ast.statements) {
            if (!stmt.role.empty() || !stmt.kvpairs.empty() || !stmt.tool_calls.empty()) {
                plan.statements_recovered++;
            }
        }

        // Determine recovery action
        if (plan.errors_found == 0) {
            plan.action = RecoveryAction::NO_ERROR;
            return plan;
        }

        if (plan.statements_recovered == 0) {
            plan.action = RecoveryAction::COMPLETE_FAILURE;
            plan.fallback_json = generate_fallback_json(ast, plan);
        } else if (plan.statements_recovered < plan.statements_total) {
            plan.action = RecoveryAction::PARTIAL_SUCCESS;
            plan.recovery_instruction = generate_recovery_instruction(ast, plan, original_payload);
        } else {
            plan.action = RecoveryAction::REPARSE_SUGGESTED;
            plan.recovery_instruction = generate_recovery_instruction(ast, plan, original_payload);
        }

        return plan;
    }

    // Generate a recovery instruction for the Planner agent
    std::string generate_recovery_instruction(const AST& ast, const RecoveryPlan& plan, 
                                             const std::string& original_payload) {
        std::ostringstream oss;

        // The recovery frame is a space-delimited LLM-TOP header, not JSON, so
        // escape_json() does not protect it: a reqid containing a space would
        // inject additional header fields (e.g. "x AGT:admin"). Restrict the
        // value to a header-safe token instead.
        oss << "VER:LLM-TOPv1 CHK:sha256:recovery AGT:evaluator UID:system TIM:"
            << get_iso_timestamp() << " REQID:" << sanitize_header_token(ast.header.reqid)
            << "_recovery FALLBACK:json\n";

        oss << "[PLANNER] act:repair GL:fix_and_resubmit TD:correct_syntax,validate_format\n";
        oss << "ERROR_COUNT:" << plan.errors_found << " ";
        oss << "RECOVERED:" << plan.statements_recovered << "/" << plan.statements_total << "\n";

        // List specific errors
        oss << "ERRORS:\n";
        for (size_t i = 0; i < plan.error_details.size(); ++i) {
            oss << "  [" << i << "] " << plan.error_details[i] << "\n";
        }

        oss << "\nRECOVERY_HINTS:\n";
        oss << "  1. Check for unclosed quotes or brackets in the payload\n";
        oss << "  2. Verify escape sequences (\\n, \\t, \\\\, \\\")\n";
        oss << "  3. Ensure all role declarations end with ]\n";
        oss << "  4. Validate capability tokens (cap=...) have matching ttl=...\n";
        oss << "  5. Re-validate the header (VER, CHK, AGT, UID, TIM, REQID)\n";

        oss << "\nORIGINAL_PAYLOAD_HASH:djb2:" << compute_simple_hash(original_payload) << "\n";

        return oss.str();
    }

    // Generate JSON fallback when parsing fails completely
    std::string generate_fallback_json(const AST& ast, const RecoveryPlan& plan) {
        std::string js;
        size_t est_size = 512 + plan.error_details.size() * 128 + ast.statements.size() * 256;
        js.reserve(est_size);

        js += "{\n";
        js += "  \"type\": \"FALLBACK\",\n";
        js += "  \"timestamp\": \"" + get_iso_timestamp() + "\",\n";
        js += "  \"original_reqid\": \"" + escape_json(ast.header.reqid) + "\",\n";
        js += "  \"agent\": \"" + escape_json(ast.header.agt) + "\",\n";
        js += "  \"error_count\": " + std::to_string(plan.errors_found) + ",\n";
        js += "  \"recovery_status\": \"";
        
        switch (plan.action) {
            case RecoveryAction::NO_ERROR:
                js += "no_error";
                break;
            case RecoveryAction::REPARSE_SUGGESTED:
                js += "reparse_suggested";
                break;
            case RecoveryAction::PARTIAL_SUCCESS:
                js += "partial_success";
                break;
            case RecoveryAction::COMPLETE_FAILURE:
                js += "complete_failure";
                break;
        }
        
        js += "\",\n";
        js += "  \"statements_recovered\": " + std::to_string(plan.statements_recovered) + ",\n";
        js += "  \"statements_total\": " + std::to_string(plan.statements_total) + ",\n";
        js += "  \"diagnostic_messages\": [\n";

        for (size_t i = 0; i < plan.error_details.size(); ++i) {
            js += "    \"" + escape_json(plan.error_details[i]) + "\"";
            if (i + 1 < plan.error_details.size()) js += ",";
            js += "\n";
        }

        js += "  ],\n";
        js += "  \"recovered_statements\": [\n";

        // Include successfully parsed statements in JSON format
        for (size_t i = 0; i < ast.statements.size(); ++i) {
            const auto& stmt = ast.statements[i];
            js += "    {\n";
            js += "      \"role\": \"" + escape_json(stmt.role) + "\",\n";
            js += "      \"kvpairs\": {";

            bool first = true;
            for (const auto& kv : stmt.kvpairs) {
                if (!first) js += ", ";
                js += "\"" + escape_json(kv.first) + "\": \"" + escape_json(kv.second) + "\"";
                first = false;
            }

            js += "},\n";
            js += "      \"tool_count\": " + std::to_string(stmt.tool_calls.size()) + "\n";
            js += "    }";
            if (i + 1 < ast.statements.size()) js += ",";
            js += "\n";
        }

        js += "  ],\n";
        js += "  \"next_action\": \"Submit corrected payload with errors fixed\",\n";
        js += "  \"support_link\": \"https://example.com/docs/fallback-recovery\"\n";
        js += "}\n";

        return js;
    }

    // Print recovery plan to stdout for Planner/Evaluator to consume
    void print_recovery_plan(const RecoveryPlan& plan) {
        std::cout << "\n=== FALLBACK RECOVERY REPORT ===\n";
        std::cout << "Status: ";
        
        switch (plan.action) {
            case RecoveryAction::NO_ERROR:
                std::cout << "NO ERROR\n";
                break;
            case RecoveryAction::REPARSE_SUGGESTED:
                std::cout << "REPARSE SUGGESTED\n";
                std::cout << plan.recovery_instruction << "\n";
                break;
            case RecoveryAction::PARTIAL_SUCCESS:
                std::cout << "PARTIAL SUCCESS (" << plan.statements_recovered 
                          << "/" << plan.statements_total << " statements)\n";
                std::cout << plan.recovery_instruction << "\n";
                break;
            case RecoveryAction::COMPLETE_FAILURE:
                std::cout << "COMPLETE FAILURE\n";
                std::cout << "Fallback JSON:\n" << plan.fallback_json << "\n";
                break;
        }

        std::cout << "Errors Found: " << plan.errors_found << "\n";
        if (!plan.error_details.empty()) {
            std::cout << "Error Details:\n";
            for (const auto& err : plan.error_details) {
                std::cout << "  - " << err << "\n";
            }
        }
        std::cout << "==============================\n\n";
    }

private:
    // Reduce an untrusted value to something safe to embed in a space-delimited
    // protocol header: no spaces, newlines, or delimiters that could start a new
    // field. Length-capped so a huge reqid cannot bloat the recovery frame.
    static std::string sanitize_header_token(const std::string& s) {
        static constexpr size_t kMaxLen = 64;
        std::string out;
        out.reserve(std::min(s.size(), kMaxLen));
        for (char c : s) {
            if (out.size() >= kMaxLen) break;
            unsigned char uc = static_cast<unsigned char>(c);
            if (std::isalnum(uc) || c == '-' || c == '_' || c == '.') {
                out += c;
            } else {
                out += '_';
            }
        }
        if (out.empty()) out = "unknown";
        return out;
    }

    // Non-cryptographic digest used only to correlate log lines. This is the
    // djb2 variant, which seeds at 5381; it was previously seeded at 0 while
    // still being labelled djb2.
    std::string compute_simple_hash(const std::string& data) {
        uint32_t hash = 5381;
        for (char c : data) {
            hash = ((hash << 5) + hash) + static_cast<uint8_t>(c);
        }
        std::ostringstream oss;
        oss << std::hex << hash;
        return oss.str();
    }


};
