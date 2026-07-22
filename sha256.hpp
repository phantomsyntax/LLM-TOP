#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <array>
#include <vector>
#include <sstream>
#include <iomanip>

// Minimal header-only SHA-256 implementation for LLM-TOP
// Based on the FIPS 180-4 specification.
// Used for HMAC-SHA256 JWT signature verification and payload checksums.
// For production at scale, replace with OpenSSL/libsodium.

class SHA256 {
public:
    static constexpr size_t DIGEST_SIZE = 32;
    static constexpr size_t BLOCK_SIZE = 64;

    SHA256() { reset(); }

    void reset() {
        state_[0] = 0x6a09e667; state_[1] = 0xbb67ae85;
        state_[2] = 0x3c6ef372; state_[3] = 0xa54ff53a;
        state_[4] = 0x510e527f; state_[5] = 0x9b05688c;
        state_[6] = 0x1f83d9ab; state_[7] = 0x5be0cd19;
        count_ = 0;
        buf_len_ = 0;
        finalized_ = false;
    }

    // Absorb input a block at a time rather than a byte at a time. Every frame
    // is hashed for CHK, so this runs over the whole payload; the byte loop paid
    // a bounds-check and a branch per byte to do what one memcpy does.
    void update(const uint8_t* data, size_t len) {
        size_t pos = 0;

        // Top up a partially filled buffer first.
        if (buf_len_ > 0) {
            const size_t need = BLOCK_SIZE - buf_len_;
            const size_t take = (len < need) ? len : need;
            std::memcpy(buf_.data() + buf_len_, data, take);
            buf_len_ += take;
            pos += take;
            if (buf_len_ == BLOCK_SIZE) {
                transform(buf_.data());
                count_ += BLOCK_SIZE * 8;
                buf_len_ = 0;
            }
        }

        // Full blocks transform straight from the caller's memory, with no copy.
        while (pos + BLOCK_SIZE <= len) {
            transform(data + pos);
            count_ += BLOCK_SIZE * 8;
            pos += BLOCK_SIZE;
        }

        // Whatever is left is a partial block held for the next call.
        if (pos < len) {
            const size_t rest = len - pos;
            std::memcpy(buf_.data(), data + pos, rest);
            buf_len_ = rest;
        }
    }

    void update(const std::string& s) {
        update(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }

    // Produce the digest. Calling this more than once returns the same value
    // rather than hashing the padding again: finalize() mutates the state, so
    // an unguarded second call silently returned garbage.
    std::array<uint8_t, DIGEST_SIZE> finalize() {
        if (finalized_) return digest_;

        uint64_t total_bits = count_ + buf_len_ * 8;

        // Padding
        buf_[buf_len_++] = 0x80;
        if (buf_len_ > 56) {
            while (buf_len_ < BLOCK_SIZE) buf_[buf_len_++] = 0;
            transform(buf_.data());
            buf_len_ = 0;
        }
        while (buf_len_ < 56) buf_[buf_len_++] = 0;

        // Append length in big-endian
        for (int i = 7; i >= 0; --i) {
            buf_[buf_len_++] = static_cast<uint8_t>(total_bits >> (i * 8));
        }
        transform(buf_.data());

        for (int i = 0; i < 8; ++i) {
            digest_[i * 4 + 0] = static_cast<uint8_t>(state_[i] >> 24);
            digest_[i * 4 + 1] = static_cast<uint8_t>(state_[i] >> 16);
            digest_[i * 4 + 2] = static_cast<uint8_t>(state_[i] >> 8);
            digest_[i * 4 + 3] = static_cast<uint8_t>(state_[i]);
        }
        finalized_ = true;
        return digest_;
    }

    // Convenience: hash a string directly
    static std::array<uint8_t, DIGEST_SIZE> hash(const std::string& input) {
        SHA256 ctx;
        ctx.update(input);
        return ctx.finalize();
    }

    // Convenience: hash to hex string
    static std::string hash_hex(const std::string& input) {
        auto digest = hash(input);
        return to_hex(digest);
    }

    static std::string to_hex(const std::array<uint8_t, DIGEST_SIZE>& digest) {
        std::ostringstream oss;
        for (uint8_t b : digest) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        }
        return oss.str();
    }

private:
    uint32_t state_[8];
    uint64_t count_;
    size_t buf_len_;
    std::array<uint8_t, BLOCK_SIZE> buf_;
    std::array<uint8_t, DIGEST_SIZE> digest_{};
    bool finalized_ = false;

    static constexpr uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f26681, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
    static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
    static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    static uint32_t sigma0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
    static uint32_t sigma1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
    static uint32_t gamma0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
    static uint32_t gamma1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

    void transform(const uint8_t* block) {
        uint32_t W[64];
        for (int i = 0; i < 16; ++i) {
            W[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
                   (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
                   (static_cast<uint32_t>(block[i * 4 + 3]));
        }
        for (int i = 16; i < 64; ++i) {
            W[i] = gamma1(W[i - 2]) + W[i - 7] + gamma0(W[i - 15]) + W[i - 16];
        }

        uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
        uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = h + sigma1(e) + ch(e, f, g) + K[i] + W[i];
            uint32_t t2 = sigma0(a) + maj(a, b, c);
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }

        state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
        state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
    }
};

// HMAC-SHA256 implementation (RFC 2104)
class HMAC_SHA256 {
public:
    static std::array<uint8_t, SHA256::DIGEST_SIZE> compute(
            const std::string& key, const std::string& message) {
        
        std::array<uint8_t, SHA256::BLOCK_SIZE> key_block{};
        
        if (key.size() > SHA256::BLOCK_SIZE) {
            // Hash the key if it's too long
            auto hashed_key = SHA256::hash(key);
            std::memcpy(key_block.data(), hashed_key.data(), SHA256::DIGEST_SIZE);
        } else {
            std::memcpy(key_block.data(), key.data(), key.size());
        }

        // Inner padding
        std::array<uint8_t, SHA256::BLOCK_SIZE> ipad{};
        std::array<uint8_t, SHA256::BLOCK_SIZE> opad{};
        for (size_t i = 0; i < SHA256::BLOCK_SIZE; ++i) {
            ipad[i] = key_block[i] ^ 0x36;
            opad[i] = key_block[i] ^ 0x5c;
        }

        // Inner hash: SHA256(ipad || message)
        SHA256 inner;
        inner.update(ipad.data(), SHA256::BLOCK_SIZE);
        inner.update(message);
        auto inner_digest = inner.finalize();

        // Outer hash: SHA256(opad || inner_hash)
        SHA256 outer;
        outer.update(opad.data(), SHA256::BLOCK_SIZE);
        outer.update(inner_digest.data(), SHA256::DIGEST_SIZE);
        return outer.finalize();
    }

    // Convenience: compute HMAC and return as hex string
    static std::string compute_hex(const std::string& key, const std::string& message) {
        auto digest = compute(key, message);
        return SHA256::to_hex(digest);
    }

    // Constant-time comparison to prevent timing attacks
    static bool verify(const std::array<uint8_t, SHA256::DIGEST_SIZE>& a,
                       const std::array<uint8_t, SHA256::DIGEST_SIZE>& b) {
        uint8_t result = 0;
        for (size_t i = 0; i < SHA256::DIGEST_SIZE; ++i) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
};
