#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "common/hashing.h"

namespace tee {

// Transcript captures the cryptographic evidence of a single FHE evaluation.
// The server produces this; the client verifies it before trusting the result.
struct Transcript {
    // Nonce to prevent replay attacks.
    std::vector<uint8_t> nonce;

    // Blake3 hash of the evaluation key used by the server.
    Hash32 eval_key_hash{};

    // Blake3 hashes of each input ciphertext.
    std::vector<Hash32> input_ct_hashes;

    // Blake3 hash of the output ciphertext.
    Hash32 output_ct_hash{};

    // Server-reported timing fields (microseconds); not part of cryptographic hash.
    uint64_t fhe_eval_us = 0;
    uint64_t transcript_us = 0;
    uint64_t quote_us = 0;

    // Serialize to a JSON string.
    std::string to_json() const;

    // Deserialize from a JSON string.
    static Transcript from_json(const std::string& json_str);
};

}  // namespace tee
