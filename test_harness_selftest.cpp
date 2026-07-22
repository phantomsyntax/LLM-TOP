#include <stdexcept>
#include <string>
#include "test_harness.hpp"

// Regression guard for the defect that motivated the harness: the suite used
// bare assert(), which <cassert> compiles to nothing when NDEBUG is defined. A
// Release build therefore reported every target passing while evaluating no
// conditions.
//
// Phase A deliberately fails two checks with reporting silenced, then reads the
// counters. If CHECK were ever elided the way assert() was, the observed counts
// would be zero and Phase B would fail this binary.
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
