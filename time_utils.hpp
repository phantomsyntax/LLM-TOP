#pragma once
#include <string>
#include <chrono>
#include <ctime>
#include <cstdio>
#include <sstream>
#include <iomanip>
#include <optional>

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

// Parse an ISO 8601 UTC timestamp ("YYYY-MM-DDTHH:MM:SSZ") to a Unix epoch.
// Returns nullopt if the string is not a well-formed ISO 8601 UTC datetime.
inline std::optional<int64_t> parse_iso8601_to_epoch(const std::string& s) {
    int y = 0, mo = 0, d = 0, h = 0, mi = 0, se = 0;
    if (std::sscanf(s.c_str(), "%4d-%2d-%2dT%2d:%2d:%2d", &y, &mo, &d, &h, &mi, &se) != 6) {
        return std::nullopt;
    }
    if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || se > 60) {
        return std::nullopt;
    }
    std::tm tm{};
    tm.tm_year = y - 1900;
    tm.tm_mon  = mo - 1;
    tm.tm_mday = d;
    tm.tm_hour = h;
    tm.tm_min  = mi;
    tm.tm_sec  = se;
#ifdef _WIN32
    time_t t = _mkgmtime(&tm);
#else
    time_t t = timegm(&tm);
#endif
    if (t == static_cast<time_t>(-1)) return std::nullopt;
    return static_cast<int64_t>(t);
}
