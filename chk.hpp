#pragma once
#include <string>
#include "sha256.hpp"
#include "parser_v2.hpp"   // canonical_for_chk

// Producer-side CHK helpers.
//
// The middleware verifies the CHK header on every frame. Until this header
// existed there was no supported way to *produce* a frame that satisfied it --
// the only implementation lived in a test helper, so the test suite passed
// through a door no consumer had. Anyone building a frame and calling
// evaluate() got ERR:integrity with nothing in the public API to fix it.
//
// What CHK is, precisely:
//
//   CHK is an UNKEYED digest. A deliberate attacker edits the frame and
//   recomputes it, so it authenticates nothing -- authentication comes from
//   capabilities. It detects accidents: truncation, a mangled copy, a frame
//   reassembled wrong.
//
//   It is therefore only meaningful ACROSS A BOUNDARY WHERE BOTH SIDES COMPUTE
//   IT. A gateway that stamps a frame and then verifies it in the same process
//   is checking a hash against data that never left its address space. Split
//   the stamp and the check across a process or network hop and it earns its
//   keep; keep them adjacent and it is ceremony (see set_verify_chk()).
//
//   An LLM cannot compute SHA-256 of its own output, so a model-generated frame
//   never carries a valid CHK. A host ingesting LLM output stamps the frame
//   itself -- at which point CHK says nothing about the model, only about the
//   hop after the stamp.

// The CHK value a frame should carry, in "sha256:<hex>" form.
inline std::string compute_chk(const std::string& frame) {
    return "sha256:" + SHA256::hash_hex(canonical_for_chk(frame));
}

// Return `frame` with its CHK field's value replaced by the correct digest.
//
// The frame must already contain a `CHK:sha256:` marker in its header; the
// value after it may be anything (a placeholder, or empty). If no marker is
// present the frame is returned unchanged, because inserting a header field is
// a framing decision this function has no basis to make -- and a frame with no
// CHK will be rejected by a verifying middleware, which is the correct outcome.
inline std::string stamp_chk(std::string frame) {
    const std::string marker = "CHK:sha256:";
    size_t line_end = frame.find('\n');
    size_t p = frame.find(marker);
    if (p == std::string::npos) return frame;
    // Anchored to line 1, matching canonical_for_chk(). A marker in the body is
    // not a header field, and stamping it wrote a digest into a body statement
    // while leaving the frame with no header CHK at all.
    if (line_end != std::string::npos && p > line_end) return frame;

    size_t start = p + marker.size();
    size_t end = frame.find_first_of(" \r\n", start);
    if (end == std::string::npos) end = frame.size();

    // Digest the canonical form (CHK's own value blanked), then write it in.
    frame.replace(start, end - start, "");
    std::string digest = SHA256::hash_hex(canonical_for_chk(frame));
    frame.insert(start, digest);
    return frame;
}
