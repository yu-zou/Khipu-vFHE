#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "common/transcript.h"

namespace tee {

Transcript generate_transcript(
    const std::vector<uint8_t>& nonce,
    const std::vector<std::vector<uint8_t>>& eval_keys,
    const std::vector<std::vector<uint8_t>>& input_cts,
    const std::vector<uint8_t>& output_ct);

std::array<uint8_t, 32> compute_transcript_hash(const Transcript& transcript);

std::vector<uint8_t> generate_tdx_quote(
    const std::array<uint8_t, 32>& transcript_hash);

}  // namespace tee
