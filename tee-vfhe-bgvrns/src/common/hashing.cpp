#include "common/hashing.h"

#include <blake3.h>

#include <stdexcept>

namespace tee {

Hash32 blake3_hash(const uint8_t* data, std::size_t len) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    if (data != nullptr && len > 0) {
        blake3_hasher_update(&hasher, data, len);
    }
    Hash32 result{};
    blake3_hasher_finalize(&hasher, result.data(), Hash32{}.size());
    return result;
}

Hash32 blake3_hash(const std::vector<uint8_t>& data) {
    return blake3_hash(data.data(), data.size());
}

Hash32 blake3_hash(const std::string& data) {
    return blake3_hash(reinterpret_cast<const uint8_t*>(data.data()),
                       data.size());
}

namespace {

constexpr char kHexChars[] = "0123456789abcdef";

uint8_t hex_val(char c) {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
    throw std::invalid_argument("invalid hex character");
}

}  // namespace

std::string to_hex(const Hash32& hash) {
    std::string out(hash.size() * 2, '0');
    for (std::size_t i = 0; i < hash.size(); ++i) {
        out[i * 2] = kHexChars[hash[i] >> 4];
        out[i * 2 + 1] = kHexChars[hash[i] & 0x0F];
    }
    return out;
}

std::string to_hex(const std::vector<uint8_t>& bytes) {
    std::string out(bytes.size() * 2, '0');
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        out[i * 2] = kHexChars[bytes[i] >> 4];
        out[i * 2 + 1] = kHexChars[bytes[i] & 0x0F];
    }
    return out;
}

std::vector<uint8_t> from_hex(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("hex string has odd length");
    }
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        out.push_back(static_cast<uint8_t>((hex_val(hex[i]) << 4) |
                                           hex_val(hex[i + 1])));
    }
    return out;
}

Hash32 hash_from_hex(const std::string& hex) {
    if (hex.size() != Hash32{}.size() * 2) {
        throw std::invalid_argument("expected 64 hex chars for 32-byte hash");
    }
    Hash32 result{};
    for (std::size_t i = 0; i < result.size(); ++i) {
        result[i] = static_cast<uint8_t>((hex_val(hex[i * 2]) << 4) |
                                         hex_val(hex[i * 2 + 1]));
    }
    return result;
}

}  // namespace tee
