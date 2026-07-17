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

// Heterogeneous attestation (Prototype C)
std::array<uint8_t, 32> compute_gpu_evidence_digest(
    const std::vector<uint8_t>& gpu_evidence_serialized);

std::array<uint8_t, 32> compute_heterogeneous_binding_digest(
    const std::array<uint8_t, 32>& transcript_digest,
    const std::array<uint8_t, 32>& gpu_evidence_digest);

std::vector<uint8_t> generate_tdx_quote_heterogeneous(
    const std::array<uint8_t, 32>& transcript_digest,
    const std::array<uint8_t, 32>& gpu_evidence_digest);

}  // namespace tee
