# Phase 0: Make the Test Suite Capable of Failing — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the suite's `assert()`-only assertions with machinery that survives `NDEBUG`, so that every subsequent security fix in Phases 1–4 is verified by tests that can actually fail.

**Architecture:** A header-only assertion library (`test_harness.hpp`) provides `CHECK` / `CHECK_EQ` / `CHECK_CONTAINS` / `CHECK_THROWS_WITH` as ordinary function calls — never preprocessor-elided. Failures accumulate in a counter and drive a non-zero exit from `main()`. A dedicated self-test binary proves the machinery survives Release compilation, so the regression that motivated this phase cannot silently return. LLM-TOP-specific test helpers move to a second header so that the CHK definition (which Phase 1 changes) lives in exactly one place.

**Tech Stack:** C++20, CMake ≥ 3.10, MSVC (VS Community 2026) / GCC / Clang, CTest. Zero external dependencies.

## Global Constraints

- **C++20.** `CMakeLists.txt` currently pins C++17 while README and Summary claim C++20. Phase 0 resolves this by moving the build to 20, which also unblocks Phase 3's `string_view` heterogeneous lookup on `unordered_map`.
- **Zero external dependencies.** No test framework may be added. Everything is header-only and self-contained.
- **No `assert()` in any test translation unit.** `<cassert>` must not be included by `test_*.cpp` when this phase is done.
- **Header-only core.** The production headers (`parser_v2.hpp`, `middleware.hpp`, etc.) stay header-only; test code must never live inside them.
- **The build tools are not on PATH.** Use the full paths given in the verification commands below.
- **Every task ends in a commit.** One task, one commit.

### Assertion conversion rules

Every task that converts a test file applies exactly these mappings:

| Existing form | Replacement |
|---|---|
| `assert(x);` | `CHECK(x);` |
| `assert(!x);` | `CHECK(!x);` |
| `assert(a == b);` | `CHECK_EQ(a, b);` |
| `assert(a != b);` | `CHECK(a != b);` |
| `assert(s.find(t) != std::string::npos);` | `CHECK_CONTAINS(s, t);` |
| `assert(s.find(t) == std::string::npos);` | `CHECK(s.find(t) == std::string::npos);` |
| `return 0;` at end of `main()` | `return TEST_SUMMARY("<suite name>");` |
| `#include <cassert>` | `#include "test_harness.hpp"` |

There are **no** `assert(x && "message")` forms in this codebase — verified across all seven files — so no special handling is needed for that shape.

### Verification commands

```bash
CM="/c/Program Files/Microsoft Visual Studio/18/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe"
CT="/c/Program Files/Microsoft Visual Studio/18/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/ctest.exe"

"$CM" -B build -A x64
"$CM" --build build --config Debug
"$CT" --test-dir build -C Debug --output-on-failure
"$CM" --build build --config Release
"$CT" --test-dir build -C Release --output-on-failure
```

Both configurations must be green at the end of every task.

---

## File Structure

**Created:**
- `test_harness.hpp` — assertion machinery. Domain-agnostic: counters, failure reporting, the `CHECK*` macros, and `TEST_SUMMARY`. Knows nothing about LLM-TOP.
- `test_support.hpp` — LLM-TOP-specific test helpers: the shared test secret and `fix_chk()`. Separated from the harness so that Phase 1's CHK change touches one file with one responsibility.
- `test_harness_selftest.cpp` — proves `CHECK` is not elided under `NDEBUG`.

**Modified:**
- `CMakeLists.txt` — C++20, default build type, register the self-test, drop `benchmark` from CTest, drop the `WORKING_DIRECTORY` hack.
- `.gitignore` — remove the vestigial `LLM_Mock/` entry.
- `schema_validator.hpp`, `fallback_recovery.hpp` — delete dead in-header test bodies.
- `test_runner.cpp`, `test_tokenizer.cpp`, `test_schema.cpp`, `test_recovery.cpp`, `test_binary.cpp`, `test_integration.cpp`, `test_middleware.cpp` — assertion conversion.

**Two corrections to the spec.** The spec's T7 says to commit the integration fixtures by dropping `LLM_Mock/` from `.gitignore`. Both halves of that are wrong:

1. `LLM_Mock/` lives in the repository's parent directory, *outside* the git root. Git cannot track a path above the repository root, so the `.gitignore` entry never matched anything and removing it changes nothing.
2. More importantly, **the fixtures are not needed at all.** They date from the early heuristic-testing stage. Exactly one line of code opens one of them (`test_integration.cpp:62`), and what it asserts — that `std::ifstream` works and that a file contains a string someone wrote into it — exercises no LLM-TOP code. `astar.cpp` is opened by nothing; its own header comment says so. Every other `LLM_Mock` reference across the repo is a path inside a payload *string literal*, never resolved against the filesystem.

So Task 4 deletes the dependency rather than relocating it. This also resolves the fixture findings recorded in `REVIEW.md:26` and `LLM-TOP_analysis.md:63`, which Phase 4 should mark closed.

---

### Task 1: Assertion harness that survives NDEBUG

**Files:**
- Create: `test_harness.hpp`
- Create: `test_harness_selftest.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: nothing.
- Produces: macros `CHECK(expr)`, `CHECK_EQ(a, b)`, `CHECK_CONTAINS(haystack, needle)`, `CHECK_THROWS_WITH(stmt, needle)`, `TEST_SUMMARY(const char* name) -> int`. Namespace functions `llmtop_test::reset()`, `llmtop_test::set_quiet(bool)`, `llmtop_test::checks() -> int`, `llmtop_test::failures() -> int`. Every later task in every later phase uses these.

- [ ] **Step 1: Write the failing test**

Create `test_harness_selftest.cpp`:

```cpp
#include <stdexcept>
#include <string>
#include "test_harness.hpp"

// Regression guard for the defect that motivated Phase 0: the suite used bare
// assert(), which <cassert> compiles to nothing when NDEBUG is defined. A
// Release build therefore reported 9/9 passing while evaluating no conditions.
//
// Phase A below deliberately fails two checks with reporting silenced, then
// reads the counters. If CHECK were ever elided the way assert() was, the
// observed counts would be zero and Phase B would fail this binary.
int main() {
    llmtop_test::set_quiet(true);
    llmtop_test::reset();
    CHECK(1 == 2);
    CHECK_EQ(std::string("a"), std::string("b"));
    const int observed_failures = llmtop_test::failures();
    const int observed_checks = llmtop_test::checks();
    llmtop_test::reset();
    llmtop_test::set_quiet(false);

    CHECK_EQ(observed_failures, 2);
    CHECK_EQ(observed_checks, 2);

    CHECK(true);
    CHECK_CONTAINS(std::string("hello world"), std::string("o w"));
    CHECK_THROWS_WITH(throw std::runtime_error("boom"), "boom");

    return TEST_SUMMARY("harness_selftest");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `"$CM" --build build --config Debug`
Expected: FAIL — `Cannot open include file: 'test_harness.hpp'`.

- [ ] **Step 3: Write the harness**

Create `test_harness.hpp`:

```cpp
#pragma once
// Assertion machinery for the LLM-TOP test suite.
//
// Unlike <cassert>, these checks are ordinary function calls and are therefore
// NOT removed when NDEBUG is defined. A test binary built in Release reports
// failures and exits non-zero exactly as it does in Debug.
#include <cstdio>
#include <optional>
#include <ostream>
#include <sstream>
#include <string>
#include <type_traits>

namespace llmtop_test {

struct Counters {
    int checks = 0;
    int failures = 0;
    bool quiet = false;
};

inline Counters& counters() {
    static Counters c;
    return c;
}

inline void reset() {
    counters().checks = 0;
    counters().failures = 0;
}

inline void set_quiet(bool q) { counters().quiet = q; }
inline int checks() { return counters().checks; }
inline int failures() { return counters().failures; }

inline void record_pass() { ++counters().checks; }

inline void record_failure(const char* file, int line, const char* expr,
                           const std::string& detail) {
    Counters& c = counters();
    ++c.checks;
    ++c.failures;
    if (!c.quiet) {
        std::fprintf(stderr, "FAIL %s:%d: %s%s%s\n", file, line, expr,
                     detail.empty() ? "" : " -- ", detail.c_str());
    }
}

// Values are only rendered on failure, so this cold path may allocate freely.
// Types with no operator<< (std::optional, containers) degrade to a marker
// rather than failing to compile.
template <typename T, typename = void>
struct is_streamable : std::false_type {};

template <typename T>
struct is_streamable<
    T, std::void_t<decltype(std::declval<std::ostream&>() << std::declval<const T&>())>>
    : std::true_type {};

template <typename T>
inline std::string to_text(const T& v) {
    if constexpr (is_streamable<T>::value) {
        std::ostringstream oss;
        oss << v;
        return oss.str();
    } else {
        return "<unprintable>";
    }
}

template <typename T>
inline std::string to_text(const std::optional<T>& v) {
    return v.has_value() ? to_text(*v) : std::string("<nullopt>");
}

template <typename A, typename B>
inline std::string describe(const A& a, const B& b) {
    return "got [" + to_text(a) + "] want [" + to_text(b) + "]";
}

inline int summarize(const char* suite) {
    const Counters& c = counters();
    std::printf("\n%s: %d checks, %d failed\n", suite, c.checks, c.failures);
    return c.failures == 0 ? 0 : 1;
}

} // namespace llmtop_test

#define CHECK(expr)                                                                  \
    do {                                                                             \
        if (expr) {                                                                  \
            ::llmtop_test::record_pass();                                            \
        } else {                                                                     \
            ::llmtop_test::record_failure(__FILE__, __LINE__, "CHECK(" #expr ")", ""); \
        }                                                                            \
    } while (0)

#define CHECK_EQ(a, b)                                                               \
    do {                                                                             \
        const auto& lhs_ = (a);                                                       \
        const auto& rhs_ = (b);                                                       \
        if (lhs_ == rhs_) {                                                           \
            ::llmtop_test::record_pass();                                            \
        } else {                                                                     \
            ::llmtop_test::record_failure(__FILE__, __LINE__,                        \
                                          "CHECK_EQ(" #a ", " #b ")",                \
                                          ::llmtop_test::describe(lhs_, rhs_));       \
        }                                                                            \
    } while (0)

#define CHECK_CONTAINS(haystack, needle)                                             \
    do {                                                                             \
        const std::string h_ = (haystack);                                            \
        const std::string n_ = (needle);                                              \
        if (h_.find(n_) != std::string::npos) {                                       \
            ::llmtop_test::record_pass();                                            \
        } else {                                                                     \
            ::llmtop_test::record_failure(__FILE__, __LINE__,                        \
                                          "CHECK_CONTAINS(" #haystack ", " #needle ")", \
                                          "[" + h_ + "] does not contain [" + n_ + "]"); \
        }                                                                            \
    } while (0)

#define CHECK_THROWS_WITH(stmt, needle)                                              \
    do {                                                                             \
        bool threw_ = false;                                                          \
        std::string what_;                                                            \
        try {                                                                         \
            stmt;                                                                     \
        } catch (const std::exception& e_) {                                          \
            threw_ = true;                                                            \
            what_ = e_.what();                                                        \
        } catch (...) {                                                               \
            threw_ = true;                                                            \
            what_ = "<non-std exception>";                                            \
        }                                                                             \
        if (!threw_) {                                                                \
            ::llmtop_test::record_failure(__FILE__, __LINE__,                        \
                                          "CHECK_THROWS_WITH(" #stmt ")",            \
                                          "no exception thrown");                    \
        } else if (what_.find(needle) == std::string::npos) {                         \
            ::llmtop_test::record_failure(                                           \
                __FILE__, __LINE__, "CHECK_THROWS_WITH(" #stmt ")",                  \
                "message [" + what_ + "] missing [" + std::string(needle) + "]");     \
        } else {                                                                      \
            ::llmtop_test::record_pass();                                            \
        }                                                                             \
    } while (0)

#define TEST_SUMMARY(name) ::llmtop_test::summarize(name)
```

- [ ] **Step 4: Register the self-test in CMake**

In `CMakeLists.txt`, after the `add_executable(test_tokenizer test_tokenizer.cpp)` line, add:

```cmake
add_executable(test_harness_selftest test_harness_selftest.cpp)
```

and after the `add_test(NAME tokenizer_tests COMMAND test_tokenizer)` line, add:

```cmake
# Guards the Phase 0 regression: proves CHECK is not compiled out under NDEBUG.
add_test(NAME harness_selftest COMMAND test_harness_selftest)
```

- [ ] **Step 5: Run to verify it passes in both configurations**

```bash
"$CM" -B build -A x64
"$CM" --build build --config Debug && "$CT" --test-dir build -C Debug -R harness_selftest --output-on-failure
"$CM" --build build --config Release && "$CT" --test-dir build -C Release -R harness_selftest --output-on-failure
```

Expected: `harness_selftest` passes in **both**, printing `harness_selftest: 5 checks, 0 failed`.

- [ ] **Step 6: Prove the harness actually detects failure**

Temporarily change `CHECK_EQ(observed_failures, 2);` to `CHECK_EQ(observed_failures, 99);`, rebuild Release, and run.
Expected: `harness_selftest` **FAILS** in Release with a `FAIL test_harness_selftest.cpp:NN` line and a non-zero exit. Then revert the edit and confirm green again.

This step is the whole point of the phase — do not skip it.

- [ ] **Step 7: Commit**

```bash
git add test_harness.hpp test_harness_selftest.cpp CMakeLists.txt
git commit -m "test: add assertion harness that survives NDEBUG

The suite used bare assert(), which compiles to nothing under NDEBUG, so
ctest -C Release reported 9/9 passing while evaluating no conditions. These
checks are ordinary function calls that accumulate failures and drive a
non-zero exit in every configuration. test_harness_selftest guards the
regression.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Move build to C++20 and pin a default build type

**Files:**
- Modify: `CMakeLists.txt:4-5`, `CMakeLists.txt:55`

**Interfaces:**
- Consumes: nothing.
- Produces: a C++20 build. Phase 3's tokenizer optimization depends on this for heterogeneous `unordered_map` lookup.

- [ ] **Step 1: Raise the standard**

Replace `CMakeLists.txt:4-5`:

```cmake
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
```

with:

```cmake
# C++20 is required for heterogeneous lookup on unordered_map (used by the
# tokenizer's hot merge loop) and matches what the README documents.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Single-config generators leave CMAKE_BUILD_TYPE empty, which silently means
# "no optimization and no NDEBUG". Choose explicitly so behavior is predictable.
get_property(_is_multi_config GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(NOT _is_multi_config AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()
```

- [ ] **Step 2: Remove the benchmark from CTest**

Delete these three lines at `CMakeLists.txt:54-55`:

```cmake
# Optional: benchmark tests
add_test(NAME benchmark COMMAND benchmarker)
```

`benchmarker.cpp` contains zero assertions and returns 0 unconditionally, so as a CTest target it can never fail. It remains a build target and is invoked manually. Add this comment in its place:

```cmake
# benchmarker and benchmarker_real are build targets, not tests: they measure
# and report, they do not assert. Run them directly.
```

- [ ] **Step 3: Reconfigure and verify both configurations**

```bash
rm -rf build
"$CM" -B build -A x64
"$CM" --build build --config Debug && "$CT" --test-dir build -C Debug --output-on-failure
"$CM" --build build --config Release && "$CT" --test-dir build -C Release --output-on-failure
```

Expected: configure succeeds; **8** tests now run (was 9: `benchmark` removed, `harness_selftest` added). All pass in both configurations. Any new C++20 compiler diagnostic must be fixed here, not deferred.

- [ ] **Step 4: Commit**

```bash
git add CMakeLists.txt
git commit -m "build: move to C++20, pin default build type, drop benchmark from ctest

CMakeLists pinned C++17 while the README claimed C++20; C++20 is also
required for Phase 3's heterogeneous unordered_map lookup. benchmarker has no
assertions and returns 0 unconditionally, so it cannot function as a test.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Delete dead test bodies from production headers

**Files:**
- Modify: `schema_validator.hpp:209-252`, `fallback_recovery.hpp:234-259`

**Interfaces:**
- Consumes: nothing.
- Produces: nothing. Pure deletion.

`test_schema_validator()` and `test_fallback_recovery()` are `inline` functions defined in production headers. Grep confirms **nothing calls either of them** — `test_schema.cpp` and `test_recovery.cpp` both have their own `main()` with their own cases. They are dead code that also drags `<cassert>` into every consumer of those headers.

- [ ] **Step 1: Delete from `schema_validator.hpp`**

Delete from line 209 (`// Test the schema validator`) through the end of file, including the entire `inline void test_schema_validator() { ... }` body. Also remove `#include <cassert>` from line 6.

- [ ] **Step 2: Delete from `fallback_recovery.hpp`**

Delete from line 234 (`// Test the recovery system`) through the end of file, including the entire `inline void test_fallback_recovery() { ... }` body. Also remove `#include <cassert>` from line 10.

- [ ] **Step 3: Verify nothing referenced them**

```bash
grep -rn "test_schema_validator\|test_fallback_recovery" --include=*.cpp --include=*.hpp .
```

Expected: no output.

- [ ] **Step 4: Build and test both configurations**

```bash
"$CM" --build build --config Debug && "$CT" --test-dir build -C Debug --output-on-failure
"$CM" --build build --config Release && "$CT" --test-dir build -C Release --output-on-failure
```

Expected: 8/8 pass in both.

- [ ] **Step 5: Commit**

```bash
git add schema_validator.hpp fallback_recovery.hpp
git commit -m "refactor: delete dead test bodies from production headers

test_schema_validator() and test_fallback_recovery() were inline test
functions living in production headers with no callers, pulling <cassert>
into every consumer.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Delete the vestigial mock-fixture dependency

**Files:**
- Modify: `test_integration.cpp:1-8,29-70`
- Modify: `CMakeLists.txt:45-48`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: nothing.
- Produces: an `integration_tests` target with no filesystem dependency, so it is green on a fresh clone from any working directory.

The fixtures are leftovers from the early heuristic-testing stage. The only real read is `test_integration.cpp:62`, and it asserts that `std::ifstream` opens a file and that the file contains a string — exercising no LLM-TOP code. Deleting it removes the external dependency entirely and loses no coverage.

Coverage that genuinely belongs here — a host safely opening the path an `ExecutionPlan` approved — arrives in Phase 1 with S9, which adds sanitized arguments to the plan. That test will create its own temporary file rather than depending on a checked-in fixture.

- [ ] **Step 1: Delete the simulated-execution block**

In `test_integration.cpp`, delete this block from `run_scenario_1_auth_reader()` (lines 61–68):

```cpp
    // 4. Simulate Action Execution (Read auth_spec.txt)
    std::ifstream infile("../LLM_Mock/auth_spec.txt");
    assert(infile.good());
    std::stringstream buffer;
    buffer << infile.rdbuf();
    std::string file_content = buffer.str();
    assert(file_content.find("login(string user, string pass)") != std::string::npos);
    std::cout << "  - Dereferenced context content verification: SUCCESS.\n";
```

Leave the `std::cout << "[PASS] Integration Test 1 passed successfully.\n";` line that follows it.

- [ ] **Step 2: Drop the now-unused includes**

`<fstream>` and `<sstream>` were included only for that block. Remove both from the include list at the top of `test_integration.cpp`, leaving:

```cpp
#include "parser_v2.hpp"
#include "middleware.hpp"
#include "schema_validator.hpp"
#include <iostream>
#include <memory>
#include <cassert>
```

(`<cassert>` is replaced in Task 11.)

- [ ] **Step 3: Rename the payload paths so they stop implying a sibling directory**

The remaining `../LLM_Mock/...` occurrences are payload string content only — nothing resolves them against the filesystem. Replace them so the test does not imply a directory that no longer exists. In `test_integration.cpp`, change all of `../LLM_Mock/auth_spec.txt` to `src/auth_spec.txt` (lines 34, 40, 41) and all of `../LLM_Mock/astar.cpp` to `src/astar.cpp` (lines 77, 82, 83).

Each path appears both in a `create_token(...)` scope and in the payload body, so all occurrences must change together or authorization will fail. After editing, `grep -c "LLM_Mock" test_integration.cpp` must return `0`.

Leave `benchmarker_real.cpp` alone. Its scenarios 6 and 7 embed the same paths as payload content, and changing their length would change the token counts. Those scenarios are revisited in Phase 2 (F7), where the numbers are re-derived anyway.

- [ ] **Step 4: Drop the CWD hack from CMake**

The `WORKING_DIRECTORY` on `integration_tests` existed only so `../LLM_Mock` would resolve. Replace `CMakeLists.txt:45-48`:

```cmake
# Runs from the source dir so the fixture path "../LLM_Mock/..." resolves the same
# way regardless of where the build tree lives (in-source or out-of-source).
add_test(NAME integration_tests COMMAND test_integration
         WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
```

with:

```cmake
add_test(NAME integration_tests COMMAND test_integration)
```

- [ ] **Step 5: Remove the vestigial ignore entry**

In `.gitignore`, delete the `LLM_Mock/` line, leaving:

```
# Local mock tests
MockProject/
```

It never matched anything inside this repository — the directory is a sibling of the repo root, not a child.

- [ ] **Step 6: Verify from a directory that would previously have broken it**

```bash
"$CM" -B build -A x64 && "$CM" --build build --config Debug
cd / && "$CT" --test-dir /c/Development/LLM/LLMTOP/build -C Debug -R integration_tests --output-on-failure; cd /c/Development/LLM/LLMTOP
```

Expected: PASS. Running from `/` proves the working-directory dependence is gone. Then confirm the sibling directory is genuinely unused:

```bash
mv /c/Development/LLM/LLM_Mock /c/Development/LLM/LLM_Mock.disabled
"$CT" --test-dir build -C Debug --output-on-failure
mv /c/Development/LLM/LLM_Mock.disabled /c/Development/LLM/LLM_Mock
```

Expected: the full suite still passes with the directory renamed away.

- [ ] **Step 7: Commit**

```bash
git add test_integration.cpp CMakeLists.txt .gitignore
git commit -m "test: drop the vestigial LLM_Mock fixture dependency

The fixtures date from the early heuristic-testing stage. One line read one of
them, asserting only that ifstream works and that a file contains a string it
was written with -- no LLM-TOP code was exercised. The directory also sat
outside the git root, so a fresh clone always got a red integration_tests.

Coverage for a host safely opening an approved path arrives in Phase 1 with
the sanitized ExecutionPlan arguments, using a self-created temp file.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Consolidate duplicated test helpers

**Files:**
- Create: `test_support.hpp`
- Modify: `test_middleware.cpp:7-24`, `test_integration.cpp:10-27`

**Interfaces:**
- Consumes: `SHA256::hash_hex` from `sha256.hpp`.
- Produces: `llmtop_test::kTestSecret` (a `const std::string`) and `llmtop_test::fix_chk(std::string) -> std::string`.

`fix_chk()` is currently duplicated verbatim in two files, and `TEST_SECRET` in both. Phase 1 changes CHK to cover the whole frame, so consolidating now means that change lands in one place instead of two that can drift.

- [ ] **Step 1: Create the shared helper header**

Create `test_support.hpp`:

```cpp
#pragma once
// LLM-TOP-specific helpers shared across test translation units.
// Assertion machinery lives in test_harness.hpp; this header is about payloads.
#include <string>
#include "sha256.hpp"

namespace llmtop_test {

// Shared secret used by every test that mints capability tokens.
inline const std::string kTestSecret = "llm-top-test-secret-key-2026";

// Rewrite the CHK digest of a hand-written payload so it satisfies the
// middleware's integrity check. Kept in one place so that changing what CHK
// covers is a single-site edit.
inline std::string fix_chk(std::string payload) {
    size_t nl = payload.find('\n');
    std::string body = (nl == std::string::npos) ? std::string("") : payload.substr(nl + 1);
    std::string real = SHA256::hash_hex(body);
    const std::string marker = "CHK:sha256:";
    size_t p = payload.find(marker);
    if (p != std::string::npos) {
        size_t start = p + marker.size();
        size_t end = payload.find(' ', start);
        if (end == std::string::npos) end = (nl == std::string::npos ? payload.size() : nl);
        payload.replace(start, end - start, real);
    }
    return payload;
}

} // namespace llmtop_test
```

- [ ] **Step 2: Remove the copy in `test_middleware.cpp`**

Delete lines 6–24 (the `TEST_SECRET` definition, the `fix_chk` comment block, and the whole `static std::string fix_chk(...)` function). Add `#include "test_support.hpp"` to the include block. Add these two using-declarations below the includes so the ~40 existing call sites need no edit:

```cpp
using llmtop_test::fix_chk;
static const std::string TEST_SECRET = llmtop_test::kTestSecret;
```

- [ ] **Step 3: Remove the copy in `test_integration.cpp`**

Delete lines 10–27 (the `TEST_SECRET` definition and the `fix_chk` function). Add `#include "test_support.hpp"` and the same two using-declarations:

```cpp
using llmtop_test::fix_chk;
static const std::string TEST_SECRET = llmtop_test::kTestSecret;
```

- [ ] **Step 4: Verify only one definition remains**

```bash
grep -rn "std::string fix_chk" --include=*.cpp --include=*.hpp .
```

Expected: exactly one hit, in `test_support.hpp`.

- [ ] **Step 5: Build and test both configurations**

```bash
"$CM" --build build --config Debug && "$CT" --test-dir build -C Debug --output-on-failure
"$CM" --build build --config Release && "$CT" --test-dir build -C Release --output-on-failure
```

Expected: 8/8 pass in both.

- [ ] **Step 6: Commit**

```bash
git add test_support.hpp test_middleware.cpp test_integration.cpp
git commit -m "test: consolidate duplicated fix_chk and TEST_SECRET helpers

Both were copied verbatim into two test files. Phase 1 changes what CHK
covers, so a single definition prevents the two copies from drifting.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: Convert `test_runner.cpp` (43 assertions)

**Files:**
- Modify: `test_runner.cpp`

**Interfaces:**
- Consumes: `CHECK`, `CHECK_EQ`, `CHECK_CONTAINS`, `TEST_SUMMARY` from Task 1.
- Produces: nothing.

- [ ] **Step 1: Apply the conversion rules**

Replace `#include <cassert>` with `#include "test_harness.hpp"`, then apply the Global Constraints mapping table to all 43 assertions.

File-specific cases in this file:

- `assert(ast.diagnostic.find("Duplicate key detected") != std::string::npos);` → `CHECK_CONTAINS(ast.diagnostic, "Duplicate key detected");` — same shape for `"Invalid HR value"`, `"Self-healed unclosed quote"`, and `"Self-healed unclosed role bracket"`.
- `assert(ast.statements[0].tool_calls[0].method == "my_method");` → `CHECK_EQ(ast.statements[0].tool_calls[0].method, "my_method");` — `method` is `std::optional<std::string>`; the harness's `to_text` overload renders it, and `optional<string> == const char*` compiles.
- `assert(caught);` → `CHECK(caught);` — leave the surrounding try/catch structure alone. Do **not** rewrite these into `CHECK_THROWS_WITH` in this task; behavioral rewrites belong to Phase 1.

Change the final `return 0;` in `main()` to `return TEST_SUMMARY("core_tests");`.

- [ ] **Step 2: Verify no assertions remain**

```bash
grep -c "assert(" test_runner.cpp && grep -c "cassert" test_runner.cpp
```

Expected: `0` and `0`.

- [ ] **Step 3: Build and run in both configurations**

```bash
"$CM" --build build --config Debug && "$CT" --test-dir build -C Debug -R core_tests --output-on-failure
"$CM" --build build --config Release && "$CT" --test-dir build -C Release --output-on-failure
```

Expected: PASS in both, and the Debug run prints `core_tests: 43 checks, 0 failed`. **If the check count is not 43, an assertion was dropped during conversion — find it before continuing.**

- [ ] **Step 4: Commit**

```bash
git add test_runner.cpp
git commit -m "test: convert test_runner to the NDEBUG-safe harness

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: Convert `test_tokenizer.cpp` (11 assertions)

**Files:**
- Modify: `test_tokenizer.cpp`

**Interfaces:**
- Consumes: `CHECK`, `CHECK_EQ`, `TEST_SUMMARY` from Task 1.
- Produces: nothing.

- [ ] **Step 1: Apply the conversion rules**

Replace `#include <cassert>` with `#include "test_harness.hpp"` and apply the mapping table.

File-specific cases:

- `assert(ids.size() == 1);` → `CHECK_EQ(ids.size(), 1u);` — note the `u` suffix; `size()` is `size_t` and an unsuffixed `1` triggers a signed/unsigned comparison diagnostic at `/W4`.
- `assert(ids == expected);` → `CHECK(ids == expected);` — `std::vector<int>` has no `operator<<`, so `CHECK_EQ` would report `<unprintable>`. `CHECK` keeps the message honest.
- `assert(ids.empty());` → `CHECK(ids.empty());`
- `assert(tok.count(s) == tok.encode(s).size());` → `CHECK_EQ(tok.count(s), tok.encode(s).size());`

Change the final `return 0;` to `return TEST_SUMMARY("tokenizer_tests");`.

- [ ] **Step 2: Verify no assertions remain**

```bash
grep -c "assert(" test_tokenizer.cpp && grep -c "cassert" test_tokenizer.cpp
```

Expected: `0` and `0`.

- [ ] **Step 3: Build and run in both configurations**

```bash
"$CM" --build build --config Debug && "$CT" --test-dir build -C Debug -R tokenizer_tests --output-on-failure
"$CM" --build build --config Release && "$CT" --test-dir build -C Release --output-on-failure
```

Expected: PASS in both; Debug prints `tokenizer_tests: 11 checks, 0 failed`.

- [ ] **Step 4: Commit**

```bash
git add test_tokenizer.cpp
git commit -m "test: convert test_tokenizer to the NDEBUG-safe harness

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 8: Convert `test_schema.cpp` (7 assertions)

**Files:**
- Modify: `test_schema.cpp`

**Interfaces:**
- Consumes: `CHECK`, `TEST_SUMMARY` from Task 1.
- Produces: nothing.

- [ ] **Step 1: Apply the conversion rules**

Replace `#include <cassert>` with `#include "test_harness.hpp"`. All seven assertions in this file are plain boolean predicates and map directly to `CHECK`:

```cpp
CHECK(result.valid);          // Test 1, Test 3, Test 5
CHECK(!result.valid);         // Test 2
CHECK(!result.errors.empty());   // Test 2
CHECK(!result.warnings.empty()); // Test 3, Test 4
```

Change the final `return 0;` to `return TEST_SUMMARY("schema_tests");`.

Leave the assertions' *meaning* alone. Phase 1 (T8) changes the schema validator so that a missing capability becomes an error rather than a warning; that will require editing Test 4's expectation. Doing it here would mix a mechanical conversion with a behavioral change.

- [ ] **Step 2: Verify no assertions remain**

```bash
grep -c "assert(" test_schema.cpp && grep -c "cassert" test_schema.cpp
```

Expected: `0` and `0`.

- [ ] **Step 3: Build and run in both configurations**

```bash
"$CM" --build build --config Debug && "$CT" --test-dir build -C Debug -R schema_tests --output-on-failure
"$CM" --build build --config Release && "$CT" --test-dir build -C Release --output-on-failure
```

Expected: PASS in both; Debug prints `schema_tests: 7 checks, 0 failed`.

- [ ] **Step 4: Commit**

```bash
git add test_schema.cpp
git commit -m "test: convert test_schema to the NDEBUG-safe harness

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 9: Convert `test_recovery.cpp` (25 assertions)

**Files:**
- Modify: `test_recovery.cpp`

**Interfaces:**
- Consumes: `CHECK`, `CHECK_EQ`, `CHECK_CONTAINS`, `TEST_SUMMARY` from Task 1.
- Produces: nothing.

- [ ] **Step 1: Apply the conversion rules**

Replace `#include <cassert>` with `#include "test_harness.hpp"` and apply the mapping table.

File-specific cases:

- `assert(!plan.recovery_instruction.empty());` → `CHECK(!plan.recovery_instruction.empty());` — same shape for `plan.fallback_json`.
- `assert(js.find("req\\\"evil") != std::string::npos);` (Test 7) → `CHECK_CONTAINS(js, "req\\\"evil");` — preserve the escaping exactly as written; this asserts the JSON escaper emitted a backslash-quote sequence.
- `assert(plan.errors_found > 0);` → `CHECK(plan.errors_found > 0);` — a relational comparison, so `CHECK`, not `CHECK_EQ`.

Change the final `return 0;` to `return TEST_SUMMARY("recovery_tests");`.

- [ ] **Step 2: Verify no assertions remain**

```bash
grep -c "assert(" test_recovery.cpp && grep -c "cassert" test_recovery.cpp
```

Expected: `0` and `0`.

- [ ] **Step 3: Build and run in both configurations**

```bash
"$CM" --build build --config Debug && "$CT" --test-dir build -C Debug -R recovery_tests --output-on-failure
"$CM" --build build --config Release && "$CT" --test-dir build -C Release --output-on-failure
```

Expected: PASS in both; Debug prints `recovery_tests: 25 checks, 0 failed`.

- [ ] **Step 4: Commit**

```bash
git add test_recovery.cpp
git commit -m "test: convert test_recovery to the NDEBUG-safe harness

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 10: Convert `test_binary.cpp` (33 assertions)

**Files:**
- Modify: `test_binary.cpp`

**Interfaces:**
- Consumes: `CHECK`, `CHECK_EQ`, `TEST_SUMMARY` from Task 1.
- Produces: nothing.

- [ ] **Step 1: Apply the conversion rules**

Replace `#include <cassert>` with `#include "test_harness.hpp"` and apply the mapping table.

File-specific cases:

- `assert(decoded == original);` → `CHECK_EQ(decoded, original);` — both are `std::string`, so the failure message renders usefully.
- `assert(decoded.kvpairs.at("GL") == "fix_leak");` → `CHECK_EQ(decoded.kvpairs.at("GL"), "fix_leak");` — same shape for `"act"`.
- `assert(!decoded.tool_calls[0].method.has_value());` → `CHECK(!decoded.tool_calls[0].method.has_value());`
- `assert(arg_order == want_arg_order);` → `CHECK(arg_order == want_arg_order);` — a `std::vector`, so `CHECK` avoids an `<unprintable>` message.
- `assert(compression > 0.0f);` and `assert(compression > 15.0f);` → `CHECK(compression > 0.0f);` / `CHECK(compression > 15.0f);` — relational, so `CHECK`.
- `assert(batch.size() == 500);` → `CHECK_EQ(batch.size(), 500u);` — note the `u` suffix.

Change the final `return 0;` to `return TEST_SUMMARY("binary_tests");`.

- [ ] **Step 2: Verify no assertions remain**

```bash
grep -c "assert(" test_binary.cpp && grep -c "cassert" test_binary.cpp
```

Expected: `0` and `0`.

- [ ] **Step 3: Build and run in both configurations**

```bash
"$CM" --build build --config Debug && "$CT" --test-dir build -C Debug -R binary_tests --output-on-failure
"$CM" --build build --config Release && "$CT" --test-dir build -C Release --output-on-failure
```

Expected: PASS in both; Debug prints `binary_tests: 33 checks, 0 failed`.

- [ ] **Step 4: Commit**

```bash
git add test_binary.cpp
git commit -m "test: convert test_binary to the NDEBUG-safe harness

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 11: Convert `test_integration.cpp` (6 assertions)

**Files:**
- Modify: `test_integration.cpp`

**Interfaces:**
- Consumes: `CHECK`, `CHECK_EQ`, `TEST_SUMMARY` from Task 1; `fix_chk`, `kTestSecret` from Task 5.
- Produces: nothing.

Task 4 removed the two filesystem assertions, so six remain — three per scenario.

- [ ] **Step 1: Apply the conversion rules**

Replace `#include <cassert>` with `#include "test_harness.hpp"` and apply the mapping table.

File-specific cases, each appearing once per scenario:

- `assert(ast.statements.size() == 1);` → `CHECK_EQ(ast.statements.size(), 1u);` — note the `u` suffix.
- `assert(schema_res.valid);` → `CHECK(schema_res.valid);`
- `assert(plan.authorized);` → `CHECK(plan.authorized);`

Change the final `return 0;` to `return TEST_SUMMARY("integration_tests");`.

Note: `CHECK` does not abort the process the way `assert` did, so a failed authorization no longer stops the scenario — later checks still run and report. That is intended; the suite reports every failure rather than only the first.

- [ ] **Step 2: Verify no assertions remain**

```bash
grep -c "assert(" test_integration.cpp && grep -c "cassert" test_integration.cpp
```

Expected: `0` and `0`.

- [ ] **Step 3: Build and run in both configurations**

```bash
"$CM" --build build --config Debug && "$CT" --test-dir build -C Debug -R integration_tests --output-on-failure
"$CM" --build build --config Release && "$CT" --test-dir build -C Release --output-on-failure
```

Expected: PASS in both; Debug prints `integration_tests: 6 checks, 0 failed`.

- [ ] **Step 4: Commit**

```bash
git add test_integration.cpp
git commit -m "test: convert test_integration to the NDEBUG-safe harness

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 12: Convert `test_middleware.cpp` (47 assertions)

**Files:**
- Modify: `test_middleware.cpp`

**Interfaces:**
- Consumes: `CHECK`, `CHECK_EQ`, `CHECK_CONTAINS`, `TEST_SUMMARY` from Task 1; `fix_chk`, `kTestSecret` from Task 5.
- Produces: nothing.

This is the security-critical file and the largest conversion. Every assertion here guards a Phase 1 fix, so a dropped one is a silently unguarded security behavior.

- [ ] **Step 1: Apply the conversion rules**

Replace `#include <cassert>` with `#include "test_harness.hpp"` and apply the mapping table.

File-specific cases:

- `assert(plan.authorized == true);` → `CHECK(plan.authorized);` — and `assert(plan.authorized == false);` → `CHECK(!plan.authorized);`. Comparing a `bool` to a `bool` literal adds nothing.
- `assert(plan.error_message.find("ERR:cap_invalid_or_expired") != std::string::npos);` → `CHECK_CONTAINS(plan.error_message, "ERR:cap_invalid_or_expired");` — this shape recurs for `"ERR:exec - Unauthorized tool call"`, `"ERR:auth_rejected"`, `"ERR:integrity"`, `"ERR:replay_detected"`, `"ERR:cap_required"`, `"Unauthorized tool call"`, and `"Unauthorized tool call: write"`.
- `assert(plan.approved_actions.size() == 2);` → `CHECK_EQ(plan.approved_actions.size(), 2u);` — note the `u` suffix.
- `assert(decoded == original);` in `test_base64url_roundtrip` → `CHECK_EQ(decoded, original);`.
- `assert(claim.valid);` → `CHECK(claim.valid);`; `assert(claim.scope == "execute:read");` → `CHECK_EQ(claim.scope, "execute:read");`.
- `assert(caught);` in the input-size-limit case → `CHECK(caught);`. Leave the try/catch alone.
- The four `assert(SimpleJWTValidator::scope_matches(...) == true/false);` in `test_multi_depth_glob_matching` → `CHECK(SimpleJWTValidator::scope_matches(...));` and `CHECK(!SimpleJWTValidator::scope_matches(...));`.

Change the final `return 0;` to `return TEST_SUMMARY("middleware_tests");`.

**Do not add, remove, or change the meaning of any assertion in this task.** Phase 1 rewrites several of these (notably the glob cases in `test_multi_depth_glob_matching` and the mislabeled alg case in `test_security_hardening`). Mixing that into a mechanical conversion would make the security change unreviewable.

- [ ] **Step 2: Verify no assertions remain**

```bash
grep -c "assert(" test_middleware.cpp && grep -c "cassert" test_middleware.cpp
```

Expected: `0` and `0`.

- [ ] **Step 3: Build and run in both configurations**

```bash
"$CM" --build build --config Debug && "$CT" --test-dir build -C Debug -R middleware_tests --output-on-failure
"$CM" --build build --config Release && "$CT" --test-dir build -C Release --output-on-failure
```

Expected: PASS in both; Debug prints `middleware_tests: 146 checks, 0 failed`.

The runtime count is 146, not 47, because `test_base64url_roundtrip` runs its single `CHECK_EQ` inside a 100-iteration loop: 46 + 100 = 146. **Runtime check counts only equal static assertion counts when no assertion sits in a loop** — verify the static count with the grep in Step 2 (47 `CHECK*` macros, zero residual `assert(`), and treat the runtime number as a separate expectation.

- [ ] **Step 4: Commit**

```bash
git add test_middleware.cpp
git commit -m "test: convert test_middleware to the NDEBUG-safe harness

47 assertions guarding the capability boundary, converted mechanically with no
change in meaning. Phase 1 rewrites several of them; keeping that separate
keeps the security change reviewable.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 13: Phase 0 verification gate

**Files:**
- Modify: `README.md:36-55` (build and test instructions)

**Interfaces:**
- Consumes: everything from Tasks 1–12.
- Produces: a suite that provably fails when behavior regresses, in both configurations.

- [ ] **Step 1: Confirm the suite is assertion-free**

```bash
grep -rn "assert(" --include=test_*.cpp . ; grep -rln "cassert" --include=*.cpp --include=*.hpp .
```

Expected: no output from either command.

- [ ] **Step 2: Confirm total check counts**

```bash
"$CM" --build build --config Debug && "$CT" --test-dir build -C Debug --output-on-failure
```

Expected: 8/8 pass, with two distinct counts to verify.

**Static assertions** (what the grep in each conversion task checks): 43 core + 47 middleware + 33 binary + 25 recovery + 11 tokenizer + 6 integration + 7 schema = **172**. That is 172 rather than the 174 originally in the files because Task 4 removed the two filesystem assertions along with the fixture dependency.

**Runtime checks** (what the suites print): **271**, plus 5 from `harness_selftest`. The 99-check difference is `test_base64url_roundtrip`, whose single `CHECK_EQ` executes 100 times inside a loop. Do not expect these two numbers to match.

- [ ] **Step 3: Prove the suite fails on a real regression, in Release**

Introduce a deliberate behavioral break — in `middleware.hpp`, change `is_pointer_key` to `return false;`:

```cpp
static bool is_pointer_key(const std::string& key) {
    return false;  // TEMPORARY — proving the suite detects regressions
}
```

Then:

```bash
"$CM" --build build --config Release && "$CT" --test-dir build -C Release --output-on-failure
```

Expected: `middleware_tests` **FAILS** with named `FAIL test_middleware.cpp:NN` lines. Before Phase 0 this exact break passed 9/9 in Release.

Revert the change and confirm green again:

```bash
git checkout middleware.hpp
"$CM" --build build --config Release && "$CT" --test-dir build -C Release --output-on-failure
```

- [ ] **Step 4: Correct the build instructions**

In `README.md`, replace the "Building and Testing" block (lines 36–55) with:

````markdown
## Building and Testing

Built with standard CMake and a C++20 toolchain (MSVC / GCC / Clang), no external
dependencies:

```bash
cmake -B build
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

The suite is also expected to pass in Release. Assertions are ordinary function
calls, not `assert()`, so they are not compiled out under `NDEBUG`:

```bash
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

To run a single test binary directly:

```bash
.\build\Debug\test_middleware.exe
.\build\Debug\fuzzer.exe
```
````

This drops the stale `fuzzer.exe 2000` invocation — `fuzzer.cpp`'s `main()` takes no arguments — and stops listing `benchmarker` as a test.

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs: correct build and test instructions

The suite now passes in Release as well as Debug, because assertions are no
longer compiled out under NDEBUG. Drops the stale 'fuzzer.exe 2000' invocation;
fuzzer's main() takes no arguments.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Phase 0 Done When

- No `assert(` or `<cassert>` remains in any test translation unit.
- `ctest` is green in **both** Debug and Release, 8/8.
- Deliberately breaking `is_pointer_key` turns the suite red **in Release**.
- `harness_selftest` guards the elision regression permanently.
- A fresh clone runs `integration_tests` green, and the whole suite still passes with the `../LLM_Mock` sibling directory renamed away.
- `fix_chk` has exactly one definition, ready for Phase 1 to change what CHK covers.

## Not In This Phase

Deliberately deferred so that mechanical conversion stays separable from behavioral change:

- Every security fix (S1–S11) — Phase 1.
- Making schema warnings into errors (T8) — Phase 1, which will require editing `test_schema.cpp` Test 4.
- Rewriting the glob assertions to catch S2, and replacing the mislabeled alg test (T3, T4) — Phase 1.
- Extending the fuzzer past the parser (T5) — Phase 1.
- Deleting Python and rebuilding measurement (Phase 2).
- Tokenizer and SHA-256 optimization (Phase 3).
- The remaining documentation reconciliation (Phase 4).
