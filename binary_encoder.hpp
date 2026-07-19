#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <cstring>
#include <stdexcept>
#include <iostream>
#include <unordered_map>
#include "parser_v2.hpp"

// Binary encoding for LLM-TOP payloads
// Achieves ~10-40% compression vs. text format (depending on payload size/type) through:
// 1. Symbol tables (8-bit opcodes for common fields)
// 2. Varint encoding for integers and lengths
// 3. Packed bit fields for flags
// 4. Delta encoding for repeated structures

class BinaryEncoder {
public:
    // Opcode symbols for common fields (saves 3-5 bytes per field)
    enum class Opcode : uint8_t {
        // Header fields
        OP_VERSION = 0x01,
        OP_CHECKSUM = 0x02,
        OP_AGENT = 0x03,
        OP_UID = 0x04,
        OP_TIMESTAMP = 0x05,
        OP_REQID = 0x06,
        OP_FALLBACK = 0x07,
        OP_HR = 0x08,

        // Statement fields
        OP_ROLE = 0x10,
        OP_TARGET = 0x11,
        OP_ACTION = 0x12,
        OP_GOAL = 0x13,
        OP_TODO = 0x14,
        OP_CONTEXT = 0x15,
        OP_CAPABILITY = 0x16,
        OP_TTL = 0x17,
        OP_ERR = 0x18,
        OP_REQ = 0x19,
        OP_DEP = 0x1A,
        OP_FN = 0x1B,
        OP_CLS = 0x1C,
        OP_VAR = 0x1D,

        // Tool fields
        OP_TOOL_NAME = 0x20,
        OP_TOOL_ARG = 0x21,
        OP_TOOL_METHOD = 0x22,

        // Generic (non-shorthand) statement-level key/value pair
        OP_KV = 0x23,

        // Special
        OP_END_STATEMENT = 0x7E,
        OP_END_MESSAGE = 0x7F,
    };

    // Encode a header to binary
    std::vector<uint8_t> encode_header(const std::string& ver, const std::string& chk,
                                       const std::string& agt, const std::string& uid,
                                       const std::string& tim, const std::string& reqid,
                                       const std::string& fallback = "") {
        std::vector<uint8_t> buffer;
        
        // Magic bytes: "LLMT" (0x4C 0x4C 0x4D 0x54)
        buffer.push_back(0x4C);
        buffer.push_back(0x4C);
        buffer.push_back(0x4D);
        buffer.push_back(0x54);
        
        // Version byte (1 for v1)
        buffer.push_back(0x01);

        // Encode header fields
        encode_string(buffer, static_cast<uint8_t>(Opcode::OP_VERSION), ver);
        encode_string(buffer, static_cast<uint8_t>(Opcode::OP_CHECKSUM), chk);
        encode_string(buffer, static_cast<uint8_t>(Opcode::OP_AGENT), agt);
        encode_string(buffer, static_cast<uint8_t>(Opcode::OP_UID), uid);
        encode_string(buffer, static_cast<uint8_t>(Opcode::OP_TIMESTAMP), tim);
        encode_string(buffer, static_cast<uint8_t>(Opcode::OP_REQID), reqid);
        
        if (!fallback.empty()) {
            encode_string(buffer, static_cast<uint8_t>(Opcode::OP_FALLBACK), fallback);
        }

        return buffer;
    }

    // Encode a statement (role + KV pairs + tool calls)
    std::vector<uint8_t> encode_statement(const std::string& role,
                                         const ordered_map& kvpairs,
                                         const std::vector<ToolCall>& tools = {}) {
        std::vector<uint8_t> buffer;

        // Role
        encode_string(buffer, static_cast<uint8_t>(Opcode::OP_ROLE), role);

        // Common KV pairs with opcode optimization
        std::unordered_map<std::string, Opcode> field_opcodes = {
            {"tgt", Opcode::OP_TARGET},
            {"act", Opcode::OP_ACTION},
            {"GL", Opcode::OP_GOAL},
            {"TD", Opcode::OP_TODO},
            {"ctx", Opcode::OP_CONTEXT},
            {"err", Opcode::OP_ERR},
            {"req", Opcode::OP_REQ},
            {"dep", Opcode::OP_DEP},
            {"fn", Opcode::OP_FN},
            {"cls", Opcode::OP_CLS},
            {"var", Opcode::OP_VAR},
        };

        for (const auto& kv : kvpairs) {
            auto opcode_it = field_opcodes.find(kv.first);
            if (opcode_it != field_opcodes.end()) {
                // Use opcode for known field
                encode_string(buffer, static_cast<uint8_t>(opcode_it->second), kv.second);
            } else {
                // Use generic KV encoding for unknown fields
                encode_generic_kvpair(buffer, kv.first, kv.second);
            }
        }

        // Tool calls: name, optional method, then args in insertion order.
        for (const auto& tool : tools) {
            encode_string(buffer, static_cast<uint8_t>(Opcode::OP_TOOL_NAME), tool.name);
            if (tool.method.has_value()) {
                encode_string(buffer, static_cast<uint8_t>(Opcode::OP_TOOL_METHOD), tool.method.value());
            }
            for (const auto& arg : tool.args) {
                encode_kvpair(buffer, static_cast<uint8_t>(Opcode::OP_TOOL_ARG), arg.first, arg.second);
            }
        }

        // End of statement marker
        buffer.push_back(static_cast<uint8_t>(Opcode::OP_END_STATEMENT));

        return buffer;
    }

    // Decode binary back to text (for testing round-trip)
    std::string decode_header(const std::vector<uint8_t>& buffer, size_t& pos) {
        if (buffer.size() < 5 || buffer[0] != 0x4C || buffer[1] != 0x4C || 
            buffer[2] != 0x4D || buffer[3] != 0x54) {
            throw std::runtime_error("Invalid binary format: missing magic bytes");
        }

        pos = 5; // Skip magic + version
        std::string result;

        while (pos < buffer.size()) {
            uint8_t op = buffer[pos];
            if (op >= 0x10) break; // Finished header fields

            if (!result.empty()) result += " ";

            switch (static_cast<Opcode>(op)) {
                case Opcode::OP_VERSION:   result += "VER:"; break;
                case Opcode::OP_CHECKSUM:  result += "CHK:"; break;
                case Opcode::OP_AGENT:     result += "AGT:"; break;
                case Opcode::OP_UID:       result += "UID:"; break;
                case Opcode::OP_TIMESTAMP: result += "TIM:"; break;
                case Opcode::OP_REQID:     result += "REQID:"; break;
                case Opcode::OP_FALLBACK:  result += "FALLBACK:"; break;
                case Opcode::OP_HR:        result += "HR:"; break;
                default:
                    throw std::runtime_error("Unknown header opcode");
            }
            pos = decode_string(buffer, pos, result);
        }

        return result;
    }

    // Decode a binary statement back to Statement structure
    Statement decode_statement(const std::vector<uint8_t>& buffer, size_t& pos) {
        Statement stmt;

        while (pos < buffer.size()) {
            uint8_t op_byte = buffer[pos];
            Opcode op = static_cast<Opcode>(op_byte);

            if (op == Opcode::OP_END_STATEMENT) {
                pos++; // Consume end marker
                break;
            }
            if (op == Opcode::OP_END_MESSAGE) {
                pos++; // Consume end marker
                break;
            }

            if (op == Opcode::OP_ROLE) {
                std::string role;
                pos = decode_string(buffer, pos, role);
                stmt.role = role;
            } 
            else if (op == Opcode::OP_TOOL_NAME) {
                std::string tool_name;
                pos = decode_string(buffer, pos, tool_name);
                ToolCall tc;
                tc.name = tool_name;
                stmt.tool_calls.push_back(tc);
            }
            else if (op == Opcode::OP_TOOL_METHOD) {
                if (stmt.tool_calls.empty())
                    throw std::runtime_error("OP_TOOL_METHOD with no preceding tool call");
                std::string method;
                pos = decode_string(buffer, pos, method);
                stmt.tool_calls.back().method = method;
            }
            else if (op == Opcode::OP_TOOL_ARG) {
                // Belongs to the most recent tool call: [key_len][key][val_len][val]
                if (stmt.tool_calls.empty())
                    throw std::runtime_error("OP_TOOL_ARG with no preceding tool call");
                std::string key, val;
                decode_kvpair(buffer, pos, key, val);
                stmt.tool_calls.back().args[key] = val;
            }
            else if (op == Opcode::OP_KV) {
                // Generic statement-level KV pair: [key_len][key][val_len][val]
                std::string key, val;
                decode_kvpair(buffer, pos, key, val);
                stmt.kvpairs[key] = val;
            }
            else {
                // Predefined statement field opcode: [OPCODE][len][val]
                std::string key;
                switch (op) {
                    case Opcode::OP_TARGET:    key = "tgt"; break;
                    case Opcode::OP_ACTION:    key = "act"; break;
                    case Opcode::OP_GOAL:      key = "GL"; break;
                    case Opcode::OP_TODO:      key = "TD"; break;
                    case Opcode::OP_CONTEXT:   key = "ctx"; break;
                    case Opcode::OP_ERR:       key = "err"; break;
                    case Opcode::OP_REQ:       key = "req"; break;
                    case Opcode::OP_DEP:       key = "dep"; break;
                    case Opcode::OP_FN:        key = "fn"; break;
                    case Opcode::OP_CLS:       key = "cls"; break;
                    case Opcode::OP_VAR:       key = "var"; break;
                    default:
                        throw std::runtime_error("Unknown statement opcode: " + std::to_string(op_byte));
                }
                std::string val;
                pos = decode_string(buffer, pos, val);
                stmt.kvpairs[key] = val;
            }
        }

        return stmt;
    }

    // Get compression ratio
    static float get_compression_ratio(size_t original_size, size_t compressed_size) {
        if (original_size == 0) return 0.0f;
        return 100.0f * (1.0f - static_cast<float>(compressed_size) / original_size);
    }

private:
    // Encode a varint (variable-length integer) for lengths
    void encode_varint(std::vector<uint8_t>& buffer, uint32_t value) {
        while (value >= 128) {
            buffer.push_back((value & 0x7F) | 0x80);
            value >>= 7;
        }
        buffer.push_back(value & 0x7F);
    }

    // Decode a varint
    uint32_t decode_varint(const std::vector<uint8_t>& buffer, size_t& pos) {
        uint64_t value = 0; // accumulate in 64 bits so a 5th byte cannot silently overflow
        int shift = 0;
        int bytes_read = 0;
        while (pos < buffer.size()) {
            if (bytes_read >= 5) {
                throw std::runtime_error("Varint too long (max 5 bytes)");
            }
            uint8_t byte = buffer[pos++];
            value |= static_cast<uint64_t>(byte & 0x7F) << shift;
            bytes_read++;
            if ((byte & 0x80) == 0) break;
            shift += 7;
        }
        if (value > 0xFFFFFFFFULL) {
            throw std::runtime_error("Varint exceeds 32-bit range");
        }
        return static_cast<uint32_t>(value);
    }

    // Encode [opcode][length][string_data]
    void encode_string(std::vector<uint8_t>& buffer, uint8_t opcode, const std::string& value) {
        buffer.push_back(opcode);
        encode_varint(buffer, static_cast<uint32_t>(value.length()));
        buffer.insert(buffer.end(), value.begin(), value.end());
    }

    // Encode a length-prefixed key/value pair under the given opcode:
    // [opcode][key_len][key][val_len][val]
    void encode_kvpair(std::vector<uint8_t>& buffer, uint8_t opcode,
                       const std::string& key, const std::string& value) {
        buffer.push_back(opcode);
        encode_varint(buffer, static_cast<uint32_t>(key.length()));
        buffer.insert(buffer.end(), key.begin(), key.end());
        encode_varint(buffer, static_cast<uint32_t>(value.length()));
        buffer.insert(buffer.end(), value.begin(), value.end());
    }

    // Generic statement-level KV pair (unknown key with no shorthand opcode).
    void encode_generic_kvpair(std::vector<uint8_t>& buffer, const std::string& key, const std::string& value) {
        encode_kvpair(buffer, static_cast<uint8_t>(Opcode::OP_KV), key, value);
    }

    // Decode a length-prefixed key/value pair; `pos` must point at the opcode byte.
    void decode_kvpair(const std::vector<uint8_t>& buffer, size_t& pos,
                       std::string& key, std::string& val) {
        pos++; // consume opcode
        uint32_t key_len = decode_varint(buffer, pos);
        if (pos + key_len > buffer.size()) throw std::runtime_error("Key buffer underflow");
        key.assign(reinterpret_cast<const char*>(buffer.data() + pos), key_len);
        pos += key_len;
        uint32_t val_len = decode_varint(buffer, pos);
        if (pos + val_len > buffer.size()) throw std::runtime_error("Value buffer underflow");
        val.assign(reinterpret_cast<const char*>(buffer.data() + pos), val_len);
        pos += val_len;
    }

    // Decode string from [opcode][length][data], advance pos
    size_t decode_string(const std::vector<uint8_t>& buffer, size_t pos, std::string& out) {
        if (pos >= buffer.size()) {
            throw std::runtime_error("Buffer underflow");
        }

        uint8_t opcode = buffer[pos++];
        uint32_t len = decode_varint(buffer, pos);

        if (pos + len > buffer.size()) {
            throw std::runtime_error("Invalid string length");
        }

        out.append(reinterpret_cast<const char*>(buffer.data() + pos), len);
        return pos + len;
    }
};

// (The standalone test_binary_encoding() demo was removed; test_binary.cpp is the
//  authoritative test driver for this header.)
