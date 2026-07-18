#pragma once
#include <string>
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>

// Thread-safe time utilities for LLM-TOP
// Replaces unsafe gmtime() calls with gmtime_s() on Windows.
// Consolidates duplicate time functions from middleware.hpp and fallback_recovery.hpp.

// Get current ISO 8601 UTC timestamp string (e.g. "2026-07-18T08:00:00Z")
inline std::string get_iso_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    
    std::tm tm_buf{};
#ifdef _WIN32
    gmtime_s(&tm_buf, &time);
#else
    gmtime_r(&time, &tm_buf);
#endif

    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%FT%TZ");
    return oss.str();
}

// Get current Unix epoch timestamp
inline int64_t get_unix_timestamp() {
    auto now = std::chrono::system_clock::now();
    return static_cast<int64_t>(std::chrono::system_clock::to_time_t(now));
}
