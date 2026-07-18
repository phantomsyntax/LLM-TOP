#pragma once
#include <string>
#include <sstream>
#include <iomanip>

// Canonical JSON string escaper for LLM-TOP
// Produces RFC 8259 compliant escaped strings.
// Replaces the duplicate implementations that existed in parser_v2.hpp and fallback_recovery.hpp.

inline std::string escape_json(const std::string& s) {
    std::ostringstream o;
    for (unsigned char c : s) {
        switch (c) {
            case '"':  o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\n': o << "\\n"; break;
            case '\r': o << "\\r"; break;
            case '\t': o << "\\t"; break;
            case '\b': o << "\\b"; break;
            case '\f': o << "\\f"; break;
            default:
                if (c < 0x20) {
                    o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
                } else {
                    o << static_cast<char>(c);
                }
                break;
        }
    }
    return o.str();
}
