// llmtop_eval -- measure and validate a payload with the same code the library
// enforces with.
//
// This exists because every published token figure in this repository has to be
// reproducible from a binary in this repository. It reports real cl100k_base
// (tiktoken) BPE token counts, not character lengths and not a heuristic, and it
// reports whether a payload actually parses and validates rather than asserting
// compliance from the outside.
//
// Output is a single line of JSON on stdout so a harness can consume it directly
// (PowerShell: `| ConvertFrom-Json`). Exit status reflects whether the
// measurement could be taken, not whether the payload was valid -- validity is a
// field, because a harness usually wants to count invalid responses rather than
// abort on them.

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include "tokenizer.hpp"
#include "parser_v2.hpp"
#include "schema_validator.hpp"
#include "json_utils.hpp"
#include "chk.hpp"

#ifndef CL100K_RANKS_PATH
#define CL100K_RANKS_PATH "data/cl100k_base.tiktoken"
#endif

static void print_usage() {
    std::cout <<
        "Usage: llmtop_eval [options] [file]\n"
        "\n"
        "Reads a payload from <file>, or from stdin when <file> is '-' or omitted,\n"
        "and prints one line of JSON describing it.\n"
        "\n"
        "Options:\n"
        "  --stamp           Write the payload back out with its CHK header set to\n"
        "                    the correct digest, and exit. This is the supported way\n"
        "                    for a host to make an LLM-generated frame satisfy the\n"
        "                    middleware's integrity check. No JSON is printed.\n"
        "  --validate        Parse and schema-check the payload as LLM-TOP.\n"
        "                    Without this, only size and token count are reported.\n"
        "  --tolerant        With --validate, parse in TOLERANT mode (collect\n"
        "                    diagnostics and self-heal) instead of STRICT.\n"
        "  --ranks <path>    cl100k_base ranks file. Defaults to the path compiled in.\n"
        "  --help            Show this message.\n"
        "\n"
        "Output fields:\n"
        "  bytes             Payload size in bytes.\n"
        "  tokens            Real cl100k_base BPE token count.\n"
        "  validated         Whether --validate was requested.\n"
        "  valid             True only if the payload parsed and passed schema validation.\n"
        "  statements        Statements parsed (0 unless --validate).\n"
        "  healed            Statements the parser had to repair (--tolerant only).\n"
        "  errors            Validation error strings.\n"
        "  diagnostic        Parser diagnostic text, if any.\n"
        "\n"
        "Exit status: 0 if the measurement was taken, 1 if it could not be.\n";
}

static std::string read_all(std::istream& in) {
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

int main(int argc, char* argv[]) {
    std::string path;
    std::string ranks_path = CL100K_RANKS_PATH;
    bool validate = false;
    bool tolerant = false;
    bool stamp = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_usage();
            return 0;
        } else if (arg == "--stamp") {
            stamp = true;
        } else if (arg == "--validate") {
            validate = true;
        } else if (arg == "--tolerant") {
            tolerant = true;
        } else if (arg == "--ranks" && i + 1 < argc) {
            ranks_path = argv[++i];
        } else if (!arg.empty() && arg[0] == '-' && arg != "-") {
            std::cerr << "llmtop_eval: unknown option '" << arg << "'\n";
            return 1;
        } else if (path.empty()) {
            path = arg;
        } else {
            std::cerr << "llmtop_eval: unexpected extra argument '" << arg << "'\n";
            return 1;
        }
    }

    std::string payload;
    if (path.empty() || path == "-") {
        payload = read_all(std::cin);
    } else {
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            std::cerr << "llmtop_eval: cannot open '" << path << "'\n";
            return 1;
        }
        payload = read_all(in);
    }

    // Stamping is a producer action, not a measurement: emit the frame and stop.
    // Deliberately does not load the tokenizer, so a host can stamp frames
    // without the ranks file present.
    if (stamp) {
        std::cout << stamp_chk(payload);
        return 0;
    }

    size_t tokens = 0;
    try {
        Cl100kTokenizer tok(ranks_path);
        tokens = tok.count(payload);
    } catch (const std::exception& e) {
        // A failed count is reported as a failure rather than as a zero. A zero
        // would silently become a 100% saving in whatever table consumed it.
        std::cerr << "llmtop_eval: " << e.what() << "\n";
        return 1;
    }

    bool valid = false;
    size_t statements = 0;
    size_t healed = 0;
    std::string diagnostic;
    std::vector<std::string> errors;

    if (validate) {
        LLMTOPParser parser(tolerant ? LLMTOPParser::Mode::TOLERANT
                                     : LLMTOPParser::Mode::STRICT);
        try {
            AST ast = parser.parse(payload);
            statements = ast.statements.size();
            healed = ast.healed_draft.size();
            diagnostic = ast.diagnostic;

            SchemaValidator validator;
            auto result = validator.validate(ast);
            errors = result.errors;
            valid = result.valid && ast.diagnostic.empty();
        } catch (const std::exception& e) {
            errors.push_back(std::string("parse: ") + e.what());
            valid = false;
        }
    }

    std::cout << "{"
              << "\"bytes\":" << payload.size()
              << ",\"tokens\":" << tokens
              << ",\"validated\":" << (validate ? "true" : "false")
              << ",\"valid\":" << (valid ? "true" : "false")
              << ",\"statements\":" << statements
              << ",\"healed\":" << healed
              << ",\"errors\":[";
    for (size_t i = 0; i < errors.size(); ++i) {
        if (i) std::cout << ",";
        std::cout << "\"" << escape_json(errors[i]) << "\"";
    }
    std::cout << "],\"diagnostic\":\"" << escape_json(diagnostic) << "\"}\n";

    return 0;
}
