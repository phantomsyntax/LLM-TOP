#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <stdexcept>
#include "parser_v2.hpp"

void printUsage() {
    std::cout << "Usage: llmtop-parse [options]\n";
    std::cout << "Options:\n";
    std::cout << "  --file <path>       Path to input file containing LLM-TOP payload\n";
    std::cout << "  --mode <mode>       Parsing mode: 'strict' or 'tolerant' (default: strict)\n";
    std::cout << "  --out <path>        Path to output file for JSON/AST results\n";
    std::cout << "  --help              Show this help message\n";
}

int main(int argc, char* argv[]) {
    std::map<std::string, std::string> args;
    
    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help") {
            printUsage();
            return 0;
        } else if (arg == "--file" && i + 1 < argc) {
            args["file"] = argv[++i];
        } else if (arg == "--mode" && i + 1 < argc) {
            args["mode"] = argv[++i];
        } else if (arg == "--out" && i + 1 < argc) {
            args["out"] = argv[++i];
        } else {
            std::cerr << "Unknown or incomplete argument: " << arg << "\n";
            printUsage();
            return 1;
        }
    }

    if (args.find("file") == args.end()) {
        std::cerr << "Error: --file argument is required.\n";
        printUsage();
        return 1;
    }

    LLMTOPParser::Mode mode = LLMTOPParser::Mode::STRICT;
    if (args["mode"] == "tolerant") {
        mode = LLMTOPParser::Mode::TOLERANT;
    } else if (args["mode"] != "" && args["mode"] != "strict") {
        std::cerr << "Error: Unknown mode '" << args["mode"] << "'. Use 'strict' or 'tolerant'.\n";
        return 1;
    }

    // Read payload
    std::ifstream infile(args["file"]);
    if (!infile.is_open()) {
        std::cerr << "Error: Could not open file " << args["file"] << "\n";
        return 1;
    }
    std::string payload((std::istreambuf_iterator<char>(infile)), std::istreambuf_iterator<char>());
    infile.close();

    LLMTOPParser parser(mode);
    try {
        AST ast = parser.parse(payload);
        
        std::string output = toJson(ast);
        if (args.find("out") != args.end()) {
            std::ofstream outfile(args["out"]);
            if (!outfile.is_open()) {
                std::cerr << "Error: Could not open output file " << args["out"] << "\n";
                return 1;
            }
            outfile << output;
            outfile.close();
            std::cout << "Output written to " << args["out"] << "\n";
        } else {
            std::cout << output << "\n";
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Parse Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
