#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <optional>

// Data structures for LLM-TOP
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
};

class LLMTOPParser {
public:
    enum class Mode { STRICT, TOLERANT };

    LLMTOPParser(Mode mode = Mode::STRICT) : mode_(mode) {}

    AST parse(const std::string& payload) {
        AST ast;
        std::istringstream stream(payload);
        std::string line;

        if (!std::getline(stream, line)) {
            handleError("Empty payload");
            return ast;
        }

        // 1. Parse Header
        ast.header = parseHeader(line);

        // 2. Parse Body
        Statement current_stmt;
        bool has_role = false;

        while (std::getline(stream, line)) {
            if (line.empty()) continue;

            // Trim whitespace
            line.erase(0, line.find_first_not_of(" \r\t"));
            line.erase(line.find_last_not_of(" \r\t") + 1);

            if (line.empty()) continue;

            if (line[0] == '[') {
                if (has_role) {
                    ast.statements.push_back(current_stmt);
                    current_stmt = Statement();
                }
                size_t end_bracket = line.find(']');
                if (end_bracket == std::string::npos) {
                    handleError("Malformed role declaration: " + line);
                } else {
                    current_stmt.role = line.substr(1, end_bracket - 1);
                    has_role = true;
                    // Parse rest of the line as KV pairs
                    std::string rest = line.substr(end_bracket + 1);
                    parseKVPairs(rest, current_stmt.kvpairs);
                }
            } else if (line[0] == '!') {
                current_stmt.tool_calls.push_back(parseToolCall(line));
            } else {
                // If it's not a tool call and doesn't start with a role, assume KV pairs
                parseKVPairs(line, current_stmt.kvpairs);
            }
        }
        
        if (has_role || !current_stmt.tool_calls.empty() || !current_stmt.kvpairs.empty()) {
            ast.statements.push_back(current_stmt);
        }

        return ast;
    }

private:
    Mode mode_;

    void handleError(const std::string& msg) {
        if (mode_ == Mode::STRICT) {
            throw std::runtime_error("ERR:parse - " + msg);
        } else {
            std::cerr << "DIAGNOSTIC: " << msg << "\n";
        }
    }

    Header parseHeader(const std::string& header_line) {
        Header h;
        std::istringstream iss(header_line);
        std::string token;
        
        while (iss >> token) {
            size_t colon = token.find(':');
            if (colon == std::string::npos) {
                handleError("Malformed header token: " + token);
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
            else if (key == "HR") h.hr = std::stoi(val);
            else handleError("Unknown header key: " + key);
        }

        // Strict mode validations
        if (mode_ == Mode::STRICT) {
            if (h.ver.empty() || h.chk.empty() || h.agt.empty() || h.reqid.empty()) {
                handleError("Missing required header fields");
            }
        }
        return h;
    }

    void parseKVPairs(const std::string& line, std::unordered_map<std::string, std::string>& kvpairs) {
        std::istringstream iss(line);
        std::string token;
        while (iss >> token) {
            size_t colon = token.find(':');
            if (colon != std::string::npos) {
                std::string key = token.substr(0, colon);
                std::string val = token.substr(colon + 1);
                kvpairs[key] = val;
            } else {
                handleError("Malformed KV pair (missing colon): " + token);
            }
        }
    }

    ToolCall parseToolCall(const std::string& line) {
        ToolCall tc;
        // Format: !tool[k=v;k2=v2]>method
        std::regex re(R"(!([^\[]+)(?:\[(.*?)\])?(?:>(.+))?)");
        std::smatch match;

        if (std::regex_match(line, match, re)) {
            tc.name = match[1];
            
            std::string args_str = match[2];
            if (!args_str.empty()) {
                size_t start = 0;
                size_t end = args_str.find(';');
                while (end != std::string::npos) {
                    parseToolArg(args_str.substr(start, end - start), tc.args);
                    start = end + 1;
                    end = args_str.find(';', start);
                }
                parseToolArg(args_str.substr(start), tc.args);
            }

            if (match[3].matched) {
                tc.method = match[3];
            }
        } else {
            handleError("Malformed tool call: " + line);
        }
        return tc;
    }

    void parseToolArg(const std::string& arg, std::unordered_map<std::string, std::string>& args_map) {
        size_t eq = arg.find('=');
        if (eq != std::string::npos) {
            args_map[arg.substr(0, eq)] = arg.substr(eq + 1);
        } else {
            handleError("Malformed tool argument (missing =): " + arg);
        }
    }
};

void printAST(const AST& ast) {
    std::cout << "=== LLM-TOP AST ===\n";
    std::cout << "HEADER:\n";
    std::cout << "  VER: " << ast.header.ver << "\n";
    std::cout << "  CHK: " << ast.header.chk << "\n";
    std::cout << "  AGT: " << ast.header.agt << "\n";
    std::cout << "  UID: " << ast.header.uid << "\n";
    std::cout << "  TIM: " << ast.header.tim << "\n";
    std::cout << "  REQID: " << ast.header.reqid << "\n";
    std::cout << "  FALLBACK: " << ast.header.fallback << "\n";
    std::cout << "  HR: " << ast.header.hr << "\n\n";

    for (size_t i = 0; i < ast.statements.size(); ++i) {
        const auto& stmt = ast.statements[i];
        std::cout << "STATEMENT " << i << ":\n";
        if (!stmt.role.empty()) std::cout << "  ROLE: " << stmt.role << "\n";
        
        for (const auto& kv : stmt.kvpairs) {
            std::cout << "  KV: " << kv.first << " = " << kv.second << "\n";
        }
        
        for (const auto& tc : stmt.tool_calls) {
            std::cout << "  TOOL: " << tc.name << "\n";
            if (tc.method) std::cout << "    METHOD: " << *tc.method << "\n";
            for (const auto& arg : tc.args) {
                std::cout << "    ARG: " << arg.first << " = " << arg.second << "\n";
            }
        }
    }
}

int main() {
    std::string payload = 
        "VER:LLM-TOPv1 CHK:sha256:abcd1234 AGT:ci-agent-3 UID:ci-agent TIM:2026-07-18T08:00:00Z REQID:rq-0001 FALLBACK:json HR:1\n"
        "[RSH] tgt:src/auth.ts#L1-200:cap=eyJ...;ttl=2026-07-18T09:00:00Z act:refactor GL:fix_multi_session+add_rate_limit TD:add_tests\n"
        "!read[path=$P/src/auth.ts;cap=eyJ...;ttl=2026-07-18T09:00:00Z]\n"
        "!run[target=tests/auth.test.ts;idempotent=true;auth=cap-xyz]>test\n";

    LLMTOPParser parser(LLMTOPParser::Mode::TOLERANT);
    try {
        AST ast = parser.parse(payload);
        printAST(ast);
    } catch (const std::exception& e) {
        std::cerr << "Fatal Parse Error: " << e.what() << "\n";
    }

    return 0;
}
