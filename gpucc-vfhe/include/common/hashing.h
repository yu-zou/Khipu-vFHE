#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace tee {

// 32-byte Blake3 digest.
using Hash32 = std::array<uint8_t, 32>;

// Compute Blake3 hash of a byte buffer.
Hash32 blake3_hash(const uint8_t* data, std::size_t len);

// Compute Blake3 hash of a vector of bytes.
Hash32 blake3_hash(const std::vector<uint8_t>& data);

// Compute Blake3 hash of a string.
Hash32 blake3_hash(const std::string& data);

// Convert a 32-byte hash to a lowercase hex string (64 chars).
std::string to_hex(const Hash32& hash);

// Convert a byte vector to a lowercase hex string.
std::string to_hex(const std::vector<uint8_t>& bytes);

// Convert a hex string to a byte vector.
std::vector<uint8_t> from_hex(const std::string& hex);

// Convert a hex string to a 32-byte hash. Throws on wrong length.
Hash32 hash_from_hex(const std::string& hex);

}  // namespace tee
