#pragma once
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include <sstream>
#include <stdexcept>
#include <optional>
#include <iomanip>
#include "json_utils.hpp"

struct Header {
    std::string ver;
    std::string chk;
    std::string agt;
    std::string uid;
    std::string tim;
    std::string reqid;
    std::string fallback;
    int hr = 0;
};

struct ToolCall {
    std::string name;
    std::unordered_map<std::string, std::string> args;
    std::optional<std::string> method;
};

struct Statement {
    std::string role;
    std::unordered_map<std::string, std::string> kvpairs;
    std::vector<ToolCall> tool_calls;
};

struct AST {
    Header header;
    std::vector<Statement> statements;
    std::string diagnostic;
    bool recovery_attempted = false;
};

// escapeJson removed — use escape_json() from json_utils.hpp

inline std::string toJson(const AST& ast) {
    std::ostringstream js;
    js << "{\n  \"version\": \"" << escape_json(ast.header.ver) << "\",\n";
    js << "  \"checksum\": \"" << escape_json(ast.header.chk) << "\",\n";
    if (!ast.diagnostic.empty()) js << "  \"diagnostic\": \"" << escape_json(ast.diagnostic) << "\",\n";
    if (ast.recovery_attempted) js << "  \"recovery_attempted\": true,\n";
    js << "  \"statements\": [\n";
    for (size_t i = 0; i < ast.statements.size(); ++i) {
        const auto& stmt = ast.statements[i];
        js << "    {\n      \"role\": \"" << escape_json(stmt.role) << "\",\n      \"kvpairs\": {";
        bool first_kv = true;
        for (const auto& kv : stmt.kvpairs) {
            if (!first_kv) js << ", ";
            js << "\"" << escape_json(kv.first) << "\": \"" << escape_json(kv.second) << "\"";
            first_kv = false;
        }
        js << "},\n      \"commands\": [\n";
        for (size_t j = 0; j < stmt.tool_calls.size(); ++j) {
            const auto& tc = stmt.tool_calls[j];
            js << "        {\n          \"tool\": \"" << escape_json(tc.name) << "\",\n";
            if (tc.method) js << "          \"method\": \"" << escape_json(*tc.method) << "\",\n";
            js << "          \"args\": {";
            bool first_arg = true;
            for (const auto& arg : tc.args) {
                if (!first_arg) js << ", ";
                js << "\"" << escape_json(arg.first) << "\": \"" << escape_json(arg.second) << "\"";
                first_arg = false;
            }
            js << "}\n        }" << (j + 1 < stmt.tool_calls.size() ? "," : "") << "\n";
        }
        js << "      ]\n    }" << (i + 1 < ast.statements.size() ? "," : "") << "\n";
    }
    js << "  ]\n}\n";
    return js.str();
}

class LLMTOPParser {
public:
    enum class Mode { STRICT, TOLERANT };

    LLMTOPParser(Mode mode = Mode::STRICT) : mode_(mode) {}

    AST parse(const std::string& payload) {
        AST ast;
        std::istringstream stream(payload);
        std::string line;

        if (!std::getline(stream, line)) {
            handleError(ast, "Empty payload");
            return ast;
        }

        ast.header = parseHeader(ast, line);
        Statement current_stmt;
        bool has_role = false;

        while (std::getline(stream, line)) {
            line.erase(0, line.find_first_not_of(" \r\t"));
            line.erase(line.find_last_not_of(" \r\t") + 1);
            if (line.empty()) continue;

            // Self-healing: count unescaped quotes and append missing closing quote
            bool in_quotes = false;
            bool in_escape = false;
            for (char c : line) {
                if (in_escape) {
                    in_escape = false;
                } else if (c == '\\') {
                    in_escape = true;
                } else if (c == '"') {
                    in_quotes = !in_quotes;
                }
            }
            if (in_quotes) {
                if (mode_ == Mode::TOLERANT) {
                    line += "\"";
                    handleError(ast, "Self-healed unclosed quote in line (appended double-quote)");
                } else {
                    handleError(ast, "Malformed unclosed quote in line");
                }
            }

            if (line[0] == '[') {
                if (has_role || !current_stmt.kvpairs.empty() || !current_stmt.tool_calls.empty()) {
                    ast.statements.push_back(current_stmt);
                    current_stmt = Statement();
                }
                size_t end_bracket = line.find(']');
                if (end_bracket == std::string::npos) {
                    if (mode_ == Mode::TOLERANT) {
                        size_t first_space = line.find(' ');
                        if (first_space != std::string::npos) {
                            line.insert(first_space, "]");
                            handleError(ast, "Self-healed unclosed role bracket (inserted closing bracket)");
                        } else {
                            line += "]";
                            handleError(ast, "Self-healed unclosed role bracket (appended closing bracket)");
                        }
                        end_bracket = line.find(']');
                    }
                }

                if (end_bracket == std::string::npos) {
                    handleError(ast, "Malformed role declaration: " + line);
                } else {
                    current_stmt.role = line.substr(1, end_bracket - 1);
                    has_role = true;
                    parseKVPairs(ast, line.substr(end_bracket + 1), current_stmt.kvpairs);
                }
            } else if (line[0] == '!') {
                current_stmt.tool_calls.push_back(parseToolCall(ast, line));
            } else {
                parseKVPairs(ast, line, current_stmt.kvpairs);
            }
        }
        
        if (has_role || !current_stmt.tool_calls.empty() || !current_stmt.kvpairs.empty()) {
            ast.statements.push_back(current_stmt);
        }

        return ast;
    }

private:
    Mode mode_;

    void handleError(AST& ast, const std::string& msg) {
        if (mode_ == Mode::STRICT) {
            throw std::runtime_error("ERR:parse - " + msg);
        } else {
            ast.diagnostic += (ast.diagnostic.empty() ? "" : " | ") + msg;
            std::cerr << "DIAGNOSTIC: " << msg << "\n";
        }
    }

    std::vector<std::string> lex_split(const std::string& str, char delim) {
        std::vector<std::string> tokens;
        std::string current;
        bool in_quotes = false;
        bool in_escape = false;
        
        for (size_t i = 0; i < str.length(); ++i) {
            char c = str[i];
            
            if (in_escape) {
                current += c;
                in_escape = false;
            } else if (c == '\\' && in_quotes) {
                current += c;
                in_escape = true;
            } else if (c == '"') {
                in_quotes = !in_quotes;
                current += c;
            } else if (c == delim && !in_quotes) {
                if (!current.empty()) {
                    tokens.push_back(current);
                    current.clear();
                }
            } else {
                current += c;
            }
        }
        
        if (!current.empty()) tokens.push_back(current);
        return tokens;
    }

    std::string unquote_and_unescape(const std::string& quoted_str) {
        if (quoted_str.length() < 2 || quoted_str.front() != '"' || quoted_str.back() != '"') {
            return quoted_str;
        }
        
        std::string result;
        for (size_t i = 1; i < quoted_str.length() - 1; ++i) {
            char c = quoted_str[i];
            if (c == '\\' && i + 1 < quoted_str.length() - 1) {
                char next = quoted_str[i + 1];
                switch (next) {
                    case 'n': result += '\n'; i++; break;
                    case 't': result += '\t'; i++; break;
                    case 'r': result += '\r'; i++; break;
                    case '\\': result += '\\'; i++; break;
                    case '"': result += '"'; i++; break;
                    default: result += c;
                }
            } else {
                result += c;
            }
        }
        return result;
    }

    Header parseHeader(AST& ast, const std::string& header_line) {
        Header h;
        std::vector<std::string> tokens = lex_split(header_line, ' ');
        
        for (const auto& token : tokens) {
            size_t colon = token.find(':');
            if (colon == std::string::npos) {
                handleError(ast, "Malformed header token: " + token);
                continue;
            }
            std::string key = token.substr(0, colon);
            std::string val = token.substr(colon + 1);

            if (key == "VER") h.ver = val;
            else if (key == "CHK") h.chk = val;
            else if (key == "AGT") h.agt = val;
            else if (key == "UID") h.uid = val;
            else if (key == "TIM") h.tim = val;
            else if (key == "REQID") h.reqid = val;
            else if (key == "FALLBACK") h.fallback = val;
            else if (key == "HR") {
                try { h.hr = std::stoi(val); } 
                catch (...) { 
                    handleError(ast, "Invalid HR value: " + val + " (coerced to 0)"); 
                    h.hr = 0;
                }
            }
            else handleError(ast, "Unknown header key: " + key);
        }

        if (mode_ == Mode::STRICT) {
            if (h.ver.empty() || h.chk.empty() || h.agt.empty() || h.reqid.empty()) {
                handleError(ast, "Missing required header fields");
            }
        }
        return h;
    }

    void parseKVPairs(AST& ast, const std::string& line, std::unordered_map<std::string, std::string>& kvpairs) {
        std::vector<std::string> tokens = lex_split(line, ' ');
        for (const auto& token : tokens) {
            size_t colon = token.find(':');
            if (colon != std::string::npos) {
                std::string key = token.substr(0, colon);
                std::string val = token.substr(colon + 1);
                val = unquote_and_unescape(val);
                kvpairs[key] = val;
            } else {
                handleError(ast, "Malformed KV pair (missing colon): " + token);
            }
        }
    }

    ToolCall parseToolCall(AST& ast, const std::string& line) {
        ToolCall tc;
        size_t bracket_start = line.find('[');
        size_t bracket_end = std::string::npos;
        size_t method_marker = std::string::npos;

        if (bracket_start != std::string::npos) {
            tc.name = line.substr(1, bracket_start - 1);
            
            bool in_quotes = false;
            bool in_escape = false;
            for (size_t i = bracket_start + 1; i < line.length(); ++i) {
                char c = line[i];
                
                if (in_escape) {
                    in_escape = false;
                } else if (c == '\\' && in_quotes) {
                    in_escape = true;
                } else if (c == '"') {
                    in_quotes = !in_quotes;
                } else if (c == ']' && !in_quotes) {
                    bracket_end = i;
                    break;
                }
            }

            if (bracket_end != std::string::npos) {
                std::string args_str = line.substr(bracket_start + 1, bracket_end - bracket_start - 1);
                std::vector<std::string> args = lex_split(args_str, ';');
                for (const auto& arg : args) {
                    size_t eq = arg.find('=');
                    if (eq != std::string::npos) {
                        std::string k = arg.substr(0, eq);
                        std::string v = arg.substr(eq + 1);
                        v = unquote_and_unescape(v);
                        tc.args[k] = v;
                    } else {
                        handleError(ast, "Malformed tool argument: " + arg);
                    }
                }
                
                method_marker = line.find('>', bracket_end);
            } else {
                handleError(ast, "Malformed tool call (missing closing bracket): " + line);
            }
        } else {
            method_marker = line.find('>');
            tc.name = line.substr(1, (method_marker != std::string::npos ? method_marker - 1 : line.length() - 1));
        }

        if (method_marker != std::string::npos) {
            tc.method = line.substr(method_marker + 1);
        }

        return tc;
    }
};
