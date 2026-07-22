#pragma once
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include <deque>
#include <sstream>
#include <stdexcept>
#include <optional>
#include <iomanip>
#include "json_utils.hpp"

// Custom insertion-ordered map to maintain sequence order of protocol keys (tgt, act, etc.)
class ordered_map {
public:
    using value_type = std::pair<std::string, std::string>;
    using container_type = std::deque<value_type>;   // see the note on data_ below
    using iterator = container_type::iterator;
    using const_iterator = container_type::const_iterator;

    ordered_map() = default;

    std::string& operator[](const std::string& key) {
        auto it = index_.find(key);
        if (it != index_.end()) {
            return data_[it->second].second;
        }
        data_.emplace_back(key, "");
        index_[key] = data_.size() - 1;
        return data_.back().second;
    }

    std::string& at(const std::string& key) {
        auto it = index_.find(key);
        if (it != index_.end()) {
            return data_[it->second].second;
        }
        throw std::out_of_range("ordered_map::at: key not found");
    }

    const std::string& at(const std::string& key) const {
        auto it = index_.find(key);
        if (it != index_.end()) {
            return data_[it->second].second;
        }
        throw std::out_of_range("ordered_map::at: key not found");
    }

    iterator find(const std::string& key) {
        auto it = index_.find(key);
        if (it != index_.end()) {
            return data_.begin() + it->second;
        }
        return data_.end();
    }

    const_iterator find(const std::string& key) const {
        auto it = index_.find(key);
        if (it != index_.end()) {
            return data_.begin() + it->second;
        }
        return data_.end();
    }

    size_t count(const std::string& key) const {
        return index_.count(key);
    }

    iterator begin() { return data_.begin(); }
    const_iterator begin() const { return data_.begin(); }
    iterator end() { return data_.end(); }
    const_iterator end() const { return data_.end(); }

    bool empty() const { return data_.empty(); }
    size_t size() const { return data_.size(); }
    
    void clear() { 
        data_.clear(); 
        index_.clear(); 
    }

    // O(n) in the number of entries: the backing sequence is compacted and every
    // later index is fixed up. These maps hold a handful of keys per statement,
    // so that is the right trade against the bookkeeping a tombstone scheme would
    // need. Unlike append, erase DOES invalidate outstanding references.
    void erase(const std::string& key) {
        auto it = index_.find(key);
        if (it != index_.end()) {
            size_t idx = it->second;
            data_.erase(data_.begin() + static_cast<std::ptrdiff_t>(idx));
            index_.erase(it);
            for (auto& pair : index_) {
                if (pair.second > idx) {
                    pair.second--;
                }
            }
        }
    }

    // Named for what it does. It was called insert(), which in every standard
    // associative container leaves an existing value alone -- this overwrites it,
    // so the old name promised the opposite of the behavior.
    void insert_or_assign(const std::pair<std::string, std::string>& pair) {
        auto it = index_.find(pair.first);
        if (it != index_.end()) {
            data_[it->second].second = pair.second;
        } else {
            data_.push_back(pair);
            index_[pair.first] = data_.size() - 1;
        }
    }

private:
    // A deque, not a vector, so that appending never invalidates references to
    // existing elements. operator[] hands out a std::string& into this sequence;
    // with a vector, the sequence below was undefined behavior the moment the
    // second insertion reallocated:
    //
    //     std::string& v = m["a"];
    //     m["b"] = "x";           // vector may reallocate here
    //     v = "y";                // ... leaving v dangling
    //
    // Nothing in this repository depends on the storage being contiguous.
    container_type data_;
    std::unordered_map<std::string, size_t> index_;
};

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
    ordered_map args;
    std::optional<std::string> method;
};

struct Statement {
    std::string role;
    ordered_map kvpairs;
    std::vector<ToolCall> tool_calls;
};

struct AST {
    Header header;
    std::vector<Statement> statements;
    std::vector<Statement> healed_draft;
    std::string diagnostic;
    bool recovery_attempted = false;
    std::string raw_frame; // the entire payload, for CHK integrity verification
};

// Canonical form for CHK computation: the whole frame with the CHK header's own
// value blanked out.
//
// CHK previously digested only the body (everything after the first newline),
// which left the identity header -- AGT, UID, TIM, REQID -- outside the check.
// An agent id could therefore be rewritten in flight and the checksum still
// verified. Blanking only CHK's own value lets the digest cover the header
// without the digest having to contain itself.
//
// Note this is an UNKEYED digest: it detects truncation and corruption, not a
// deliberate attacker, who can simply recompute it. Authentication comes from
// capabilities, not from CHK.
inline std::string canonical_for_chk(const std::string& frame) {
    const std::string marker = "CHK:sha256:";
    size_t p = frame.find(marker);
    if (p == std::string::npos) return frame;
    size_t start = p + marker.size();
    size_t end = frame.find_first_of(" \r\n", start);
    if (end == std::string::npos) end = frame.size();
    std::string out = frame;
    out.erase(start, end - start);
    return out;
}

// escapeJson removed — use escape_json() from json_utils.hpp

inline std::string toJson(const AST& ast) {
    std::string js;
    size_t est_size = 256 + ast.statements.size() * 512;
    js.reserve(est_size);
    js += "{\n  \"version\": \"" + escape_json(ast.header.ver) + "\",\n";
    js += "  \"checksum\": \"" + escape_json(ast.header.chk) + "\",\n";
    js += "  \"agent\": \"" + escape_json(ast.header.agt) + "\",\n";
    js += "  \"uid\": \"" + escape_json(ast.header.uid) + "\",\n";
    js += "  \"time\": \"" + escape_json(ast.header.tim) + "\",\n";
    js += "  \"reqid\": \"" + escape_json(ast.header.reqid) + "\",\n";
    js += "  \"fallback\": \"" + escape_json(ast.header.fallback) + "\",\n";
    js += "  \"hr\": " + std::to_string(ast.header.hr) + ",\n";
    if (!ast.diagnostic.empty()) js += "  \"diagnostic\": \"" + escape_json(ast.diagnostic) + "\",\n";
    if (ast.recovery_attempted) js += "  \"recovery_attempted\": true,\n";
    js += "  \"statements\": [\n";
    for (size_t i = 0; i < ast.statements.size(); ++i) {
        const auto& stmt = ast.statements[i];
        js += "    {\n      \"role\": \"" + escape_json(stmt.role) + "\",\n      \"kvpairs\": {";
        bool first_kv = true;
        for (const auto& kv : stmt.kvpairs) {
            if (!first_kv) js += ", ";
            js += "\"" + escape_json(kv.first) + "\": \"" + escape_json(kv.second) + "\"";
            first_kv = false;
        }
        js += "},\n      \"commands\": [\n";
        for (size_t j = 0; j < stmt.tool_calls.size(); ++j) {
            const auto& tc = stmt.tool_calls[j];
            js += "        {\n          \"tool\": \"" + escape_json(tc.name) + "\",\n";
            if (tc.method) js += "          \"method\": \"" + escape_json(*tc.method) + "\",\n";
            js += "          \"args\": {";
            bool first_arg = true;
            for (const auto& arg : tc.args) {
                if (!first_arg) js += ", ";
                js += "\"" + escape_json(arg.first) + "\": \"" + escape_json(arg.second) + "\"";
                first_arg = false;
            }
            js += "}\n        }" + std::string(j + 1 < stmt.tool_calls.size() ? "," : "") + "\n";
        }
        js += "      ]\n    }" + std::string(i + 1 < ast.statements.size() ? "," : "") + "\n";
    }
    js += "  ]\n}\n";
    return js;
}

class LLMTOPParser {
public:
    enum class Mode { STRICT, TOLERANT };

    LLMTOPParser(Mode mode = Mode::STRICT, size_t max_size = 1024 * 1024) 
        : mode_(mode), max_size_(max_size) {}

    AST parse(const std::string& payload) {
        AST ast;
        if (payload.size() > max_size_) {
            handleError(ast, "Payload size exceeds maximum allowed limit");
            return ast;
        }
        // Capture the whole frame so CHK can be verified over the header too.
        ast.raw_frame = payload;
        std::istringstream stream(payload);
        std::string line;

        if (!std::getline(stream, line)) {
            handleError(ast, "Empty payload");
            return ast;
        }

        ast.header = parseHeader(ast, line);
        Statement current_stmt;
        bool has_role = false;
        bool current_stmt_healed = false;

        auto push_current_stmt = [&](Statement& stmt, bool healed) {
            if (healed) {
                ast.healed_draft.push_back(stmt);
                ast.recovery_attempted = true;
            } else {
                ast.statements.push_back(stmt);
            }
        };

        while (std::getline(stream, line)) {
            line.erase(0, line.find_first_not_of(" \r\t"));
            line.erase(line.find_last_not_of(" \r\t") + 1);
            if (line.empty()) continue;

            // A role line begins a new statement, so flush the previous one
            // BEFORE any healing on this line is recorded. Doing it the other
            // way round attributed this line's heal to the statement that came
            // before it, quarantining the clean statement and letting the
            // malformed one through as trusted.
            if (line[0] == '[' &&
                (has_role || !current_stmt.kvpairs.empty() || !current_stmt.tool_calls.empty())) {
                push_current_stmt(current_stmt, current_stmt_healed);
                current_stmt = Statement();
                current_stmt_healed = false;
            }

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
                    current_stmt_healed = true;
                } else {
                    handleError(ast, "Malformed unclosed quote in line");
                }
            }

            if (line[0] == '[') {
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
                        current_stmt_healed = true;
                        end_bracket = line.find(']');
                    }
                }

                if (end_bracket == std::string::npos) {
                    handleError(ast, "Malformed role declaration: " + line);
                } else {
                    current_stmt.role = line.substr(1, end_bracket - 1);
                    has_role = true;
                    parseKVPairs(ast, line.substr(end_bracket + 1), current_stmt.kvpairs, current_stmt_healed);
                }
            } else if (line[0] == '!') {
                current_stmt.tool_calls.push_back(parseToolCall(ast, line, current_stmt_healed));
            } else {
                parseKVPairs(ast, line, current_stmt.kvpairs, current_stmt_healed);
            }
        }
        
        if (has_role || !current_stmt.tool_calls.empty() || !current_stmt.kvpairs.empty()) {
            push_current_stmt(current_stmt, current_stmt_healed);
        }

        return ast;
    }

private:
    Mode mode_;
    size_t max_size_;

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
                    default: 
                        result += c; 
                        result += next; 
                        i++; 
                        break;
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


    std::string trim(const std::string& str) {
        size_t first = str.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) return "";
        size_t last = str.find_last_not_of(" \t\r\n");
        return str.substr(first, last - first + 1);
    }

    void parseKVPairs(AST& ast, const std::string& line, ordered_map& kvpairs, bool& current_stmt_healed) {
        std::vector<std::string> tokens = lex_split(line, ' ');
        for (const auto& token : tokens) {
            size_t colon = token.find(':');
            if (colon != std::string::npos) {
                std::string key = token.substr(0, colon);
                std::string val = token.substr(colon + 1);
                val = unquote_and_unescape(val);
                if (kvpairs.count(key) > 0) {
                    handleError(ast, "Duplicate key detected: " + key);
                    current_stmt_healed = true;
                }
                kvpairs[key] = val;
            } else {
                handleError(ast, "Malformed KV pair (missing colon): " + token);
            }
        }
    }

    ToolCall parseToolCall(AST& ast, const std::string& line, bool& current_stmt_healed) {
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
                        if (tc.args.count(k) > 0) {
                            handleError(ast, "Duplicate tool argument detected: " + k);
                            current_stmt_healed = true;
                        }
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

        tc.name = trim(tc.name);

        if (method_marker != std::string::npos) {
            tc.method = line.substr(method_marker + 1);
            tc.method = trim(*tc.method);
        }

        return tc;
    }
};
