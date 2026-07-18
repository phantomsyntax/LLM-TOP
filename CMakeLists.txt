cmake_minimum_required(VERSION 3.10)
project(LLM-TOP VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Core parser is header-only (parser_v2.hpp / middleware.hpp)

# Executables
add_executable(test_runner test_runner.cpp)
add_executable(test_middleware test_middleware.cpp)
add_executable(llmtop_parse llmtop_parse.cpp)
add_executable(benchmarker benchmarker.cpp)
add_executable(fuzzer fuzzer.cpp)

# Enable CTest
enable_testing()
add_test(NAME core_tests COMMAND test_runner)
add_test(NAME middleware_tests COMMAND test_middleware)
add_test(NAME fuzz_tests COMMAND fuzzer)
