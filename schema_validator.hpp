#pragma once
#include "parser_v2.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <cassert>

// Schema validation for LLM-TOP payloads
// Ensures messages conform to expected structure and semantics

class SchemaValidator {
public:
    enum class StatementType {
        EXEC,      // Execution / tool invocation
        CODER,     // Code generation / refactoring
        READ,      // Read file context
        PLAN,      // Planning / orchestration
        UNKNOWN
    };

    struct FieldSchema {
        std::string name;
        bool required = false;
        bool is_pointer = false;  // Requires capability token
        std::string description;
    };

    struct StatementSchema {
        StatementType type;
        std::vector<FieldSchema> required_fields;
        std::vector<FieldSchema> optional_fields;
        std::vector<std::string> allowed_tools;
    };

    SchemaValidator() {
        init_schemas();
    }

    // Validate an entire AST against expected schema
    struct ValidationResult {
        bool valid = false;
        std::vector<std::string> errors;
        std::vector<std::string> warnings;
    };

    ValidationResult validate(const AST& ast) {
        ValidationResult result;

        // 1. Validate header
        if (!validate_header(ast.header, result)) {
            return result;
        }

        // 2. Validate each statement
        for (size_t i = 0; i < ast.statements.size(); ++i) {
            if (!validate_statement(ast.statements[i], i, result)) {
                // Continue validating other statements for comprehensive error reporting
            }
        }

        // If no errors, mark as valid
        result.valid = result.errors.empty();
        return result;
    }

private:
    std::unordered_map<std::string, StatementSchema> schemas_;

    void init_schemas() {
        // EXEC schema: execution and tool invocation
        StatementSchema exec_schema;
        exec_schema.type = StatementType::EXEC;
        exec_schema.required_fields = {
            {"tgt", false, true, "Target file or function"},
            {"act", true, false, "Action (execute, call, invoke)"}
        };
        exec_schema.optional_fields = {
            {"GL", false, false, "Goal of execution"},
            {"TD", false, false, "To-do items"},
            {"ctx", false, false, "Context pointer"}
        };
        exec_schema.allowed_tools = {"run", "exec", "call"};
        schemas_["EXEC"] = exec_schema;

        // CODER schema: code generation and refactoring
        StatementSchema coder_schema;
        coder_schema.type = StatementType::CODER;
        coder_schema.required_fields = {
            {"tgt", false, true, "Target file for code generation"},
            {"act", true, false, "Action (create, refactor, fix)"},
            {"GL", true, false, "Goal of code generation"}
        };
        coder_schema.optional_fields = {
            {"TD", false, false, "To-do items"},
            {"ctx", false, false, "Context or reference"}
        };
        coder_schema.allowed_tools = {"read", "write", "gen"};
        schemas_["CODER"] = coder_schema;

        // READ schema: context reading
        StatementSchema read_schema;
        read_schema.type = StatementType::READ;
        read_schema.required_fields = {
            {"tgt", false, true, "File or memory location to read"}
        };
        read_schema.optional_fields = {
            {"range", false, false, "Line range (e.g., L1-50)"}
        };
        read_schema.allowed_tools = {"read"};
        schemas_["READ"] = read_schema;

        // PLAN schema: orchestration and planning
        StatementSchema plan_schema;
        plan_schema.type = StatementType::PLAN;
        plan_schema.required_fields = {
            {"GL", true, false, "Goal or objective"}
        };
        plan_schema.optional_fields = {
            {"TD", false, false, "To-do breakdown"},
            {"ctx", false, false, "Context or constraints"}
        };
        plan_schema.allowed_tools = {"plan", "break"};
        schemas_["PLAN"] = plan_schema;
    }

    bool validate_header(const Header& header, ValidationResult& result) {
        if (header.ver.empty()) {
            result.errors.push_back("HEADER: Missing VER field");
            return false;
        }
        if (header.agt.empty()) {
            result.errors.push_back("HEADER: Missing AGT (agent ID) field");
            return false;
        }
        if (header.reqid.empty()) {
            result.errors.push_back("HEADER: Missing REQID (request ID) field");
            return false;
        }

        // Warn if optional fields are missing
        if (header.tim.empty()) {
            result.warnings.push_back("HEADER: TIM (timestamp) should be present");
        }
        if (header.chk.empty()) {
            result.warnings.push_back("HEADER: CHK (checksum) should be present");
        }

        return true;
    }

    bool validate_statement(const Statement& stmt, size_t stmt_index, ValidationResult& result) {
        if (stmt.role.empty()) {
            result.errors.push_back("STMT[" + std::to_string(stmt_index) + "]: Missing role");
            return false;
        }

        // Look up schema for this role
        auto schema_it = schemas_.find(stmt.role);
        if (schema_it == schemas_.end()) {
            result.warnings.push_back("STMT[" + std::to_string(stmt_index) + "]: Unknown role '" + stmt.role + "' (not in schema)");
            // Don't fail on unknown roles - allow extensibility
            return true;
        }

        const auto& schema = schema_it->second;

        // Check required fields
        for (const auto& req_field : schema.required_fields) {
            auto kv_it = stmt.kvpairs.find(req_field.name);
            if (kv_it == stmt.kvpairs.end()) {
                result.errors.push_back("STMT[" + std::to_string(stmt_index) + "][" + stmt.role + 
                                       "]: Missing required field '" + req_field.name + "'");
                return false;
            }

            // If field requires capability, check for cap= and ttl=
            if (req_field.is_pointer) {
                if (kv_it->second.find("cap=") == std::string::npos) {
                    result.warnings.push_back("STMT[" + std::to_string(stmt_index) + "][" + stmt.role + 
                                             "]: Pointer field '" + req_field.name + "' missing capability token");
                }
            }
        }

        // Validate tool calls if present
        for (size_t i = 0; i < stmt.tool_calls.size(); ++i) {
            const auto& tool = stmt.tool_calls[i];
            
            // Check if tool is allowed for this role
            if (!schema.allowed_tools.empty()) {
                bool tool_allowed = false;
                for (const auto& allowed : schema.allowed_tools) {
                    if (tool.name == allowed) {
                        tool_allowed = true;
                        break;
                    }
                }
                if (!tool_allowed) {
                    result.warnings.push_back("STMT[" + std::to_string(stmt_index) + "][" + stmt.role + 
                                             "]: Tool '" + tool.name + "' not in allowed list for this role");
                }
            }
        }

        return true;
    }
};

// Test the schema validator
void test_schema_validator() {
    std::cout << "Testing SchemaValidator...\n";

    // Create a valid AST
    AST valid_ast;
    valid_ast.header.ver = "LLM-TOPv1";
    valid_ast.header.agt = "test-agent";
    valid_ast.header.reqid = "req-001";

    Statement stmt;
    stmt.role = "CODER";
    stmt.kvpairs["tgt"] = "src/main.cpp:cap=TOKEN123;ttl=2026-07-18T10:00:00Z";
    stmt.kvpairs["act"] = "refactor";
    stmt.kvpairs["GL"] = "fix_memory_leak";

    ToolCall tool;
    tool.name = "read";
    tool.args["path"] = "src/main.cpp";
    stmt.tool_calls.push_back(tool);

    valid_ast.statements.push_back(stmt);

    // Validate
    SchemaValidator validator;
    auto result = validator.validate(valid_ast);

    std::cout << "Valid AST: " << (result.valid ? "PASS" : "FAIL") << "\n";
    if (!result.errors.empty()) {
        std::cout << "Errors:\n";
        for (const auto& err : result.errors) {
            std::cout << "  - " << err << "\n";
        }
    }
    if (!result.warnings.empty()) {
        std::cout << "Warnings:\n";
        for (const auto& warn : result.warnings) {
            std::cout << "  - " << warn << "\n";
        }
    }

    assert(result.valid);
    std::cout << "[PASS] SchemaValidator test\n\n";
}
