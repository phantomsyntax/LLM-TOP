#pragma once
#include <string>
#include <sstream>
#include <iomanip>

// Canonical JSON string escaper for LLM-TOP
// Produces RFC 8259 compliant escaped strings.
// Replaces the duplicate implementations that existed in parser_v2.hpp and fallback_recovery.hpp.

inline std::string escape_json(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            default:
                if (c < 0x20) {
                    static const char hex_digits[] = "0123456789abcdef";
                    out += "\\u00";
                    out += hex_digits[(c >> 4) & 0x0F];
                    out += hex_digits[c & 0x0F];
                } else {
                    out += static_cast<char>(c);
                }
                break;
        }
    }
    return out;
}
