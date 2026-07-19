cmake_minimum_required(VERSION 3.10)
project(LLM-TOP VERSION 1.1)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Core parser is header-only:
#   - parser_v2.hpp: Enhanced lexer with escape sequence support
#   - middleware.hpp: JWT validation and capability enforcement
#   - schema_validator.hpp: Statement schema validation
#   - binary_encoder.hpp: Binary encoding with ~30-40% compression
#   - fallback_recovery.hpp: Recovery system for corrupted payloads

# Executables
add_executable(test_runner test_runner.cpp)
add_executable(test_middleware test_middleware.cpp)
add_executable(test_schema test_schema.cpp)
add_executable(test_binary test_binary.cpp)
add_executable(test_recovery test_recovery.cpp)
add_executable(test_integration test_integration.cpp)
add_executable(llmtop_parse llmtop_parse.cpp)
add_executable(benchmarker benchmarker.cpp)
add_executable(benchmarker_real benchmarker_real.cpp)
add_executable(fuzzer fuzzer.cpp)
add_executable(test_tokenizer test_tokenizer.cpp)

# The real BPE tokenizer needs the vendored cl100k_base ranks file. Pass its
# absolute path in at compile time so the targets can be run from any directory.
set(CL100K_RANKS "${CMAKE_CURRENT_SOURCE_DIR}/data/cl100k_base.tiktoken")
target_compile_definitions(test_tokenizer PRIVATE CL100K_RANKS_PATH="${CL100K_RANKS}")
target_compile_definitions(benchmarker PRIVATE CL100K_RANKS_PATH="${CL100K_RANKS}")
target_compile_definitions(benchmarker_real PRIVATE CL100K_RANKS_PATH="${CL100K_RANKS}")

# Enable CTest
enable_testing()

# Core parser tests
add_test(NAME core_tests COMMAND test_runner)
add_test(NAME middleware_tests COMMAND test_middleware)

# New feature tests
add_test(NAME schema_tests COMMAND test_schema)
add_test(NAME binary_tests COMMAND test_binary)
add_test(NAME recovery_tests COMMAND test_recovery)
# Runs from the source dir so the fixture path "../LLM_Mock/..." resolves the same
# way regardless of where the build tree lives (in-source or out-of-source).
add_test(NAME integration_tests COMMAND test_integration
         WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
add_test(NAME tokenizer_tests COMMAND test_tokenizer)

# Stability tests
add_test(NAME fuzz_tests COMMAND fuzzer)

# Optional: benchmark tests
add_test(NAME benchmark COMMAND benchmarker)
