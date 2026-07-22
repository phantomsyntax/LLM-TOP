#pragma once
// Assertion machinery for the LLM-TOP test suite.
//
// Unlike <cassert>, these checks are ordinary function calls and are therefore
// NOT removed when NDEBUG is defined. A test binary built in Release reports
// failures and exits non-zero exactly as it does in Debug.
//
// Before this header existed the suite used bare assert(), so `ctest -C Release`
// reported every target passing while evaluating no conditions at all.
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

#define CHECK(expr)                                                                    \
    do {                                                                               \
        if (expr) {                                                                    \
            ::llmtop_test::record_pass();                                              \
        } else {                                                                       \
            ::llmtop_test::record_failure(__FILE__, __LINE__, "CHECK(" #expr ")", ""); \
        }                                                                              \
    } while (0)

#define CHECK_EQ(a, b)                                                                 \
    do {                                                                               \
        const auto& lhs_ = (a);                                                        \
        const auto& rhs_ = (b);                                                        \
        if (lhs_ == rhs_) {                                                            \
            ::llmtop_test::record_pass();                                              \
        } else {                                                                       \
            ::llmtop_test::record_failure(__FILE__, __LINE__,                          \
                                          "CHECK_EQ(" #a ", " #b ")",                  \
                                          ::llmtop_test::describe(lhs_, rhs_));        \
        }                                                                              \
    } while (0)

#define CHECK_CONTAINS(haystack, needle)                                               \
    do {                                                                               \
        const std::string h_ = (haystack);                                             \
        const std::string n_ = (needle);                                               \
        if (h_.find(n_) != std::string::npos) {                                        \
            ::llmtop_test::record_pass();                                              \
        } else {                                                                       \
            ::llmtop_test::record_failure(                                             \
                __FILE__, __LINE__, "CHECK_CONTAINS(" #haystack ", " #needle ")",      \
                "[" + h_ + "] does not contain [" + n_ + "]");                         \
        }                                                                              \
    } while (0)

#define CHECK_THROWS_WITH(stmt, needle)                                                \
    do {                                                                               \
        bool threw_ = false;                                                           \
        std::string what_;                                                              \
        try {                                                                           \
            stmt;                                                                       \
        } catch (const std::exception& e_) {                                            \
            threw_ = true;                                                              \
            what_ = e_.what();                                                          \
        } catch (...) {                                                                 \
            threw_ = true;                                                              \
            what_ = "<non-std exception>";                                               \
        }                                                                               \
        if (!threw_) {                                                                   \
            ::llmtop_test::record_failure(__FILE__, __LINE__,                            \
                                          "CHECK_THROWS_WITH(" #stmt ")",               \
                                          "no exception thrown");                       \
        } else if (what_.find(needle) == std::string::npos) {                            \
            ::llmtop_test::record_failure(                                              \
                __FILE__, __LINE__, "CHECK_THROWS_WITH(" #stmt ")",                     \
                "message [" + what_ + "] missing [" + std::string(needle) + "]");        \
        } else {                                                                         \
            ::llmtop_test::record_pass();                                               \
        }                                                                                \
    } while (0)

#define TEST_SUMMARY(name) ::llmtop_test::summarize(name)
