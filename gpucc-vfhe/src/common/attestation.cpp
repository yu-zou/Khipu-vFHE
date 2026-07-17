#include "common/attestation.h"

#include <tdx_attest.h>

#include <cstring>
#include <iostream>
#include <string>

#include <nlohmann/json.hpp>

#include "common/hashing.h"

namespace tee {

namespace {

Hash32 hash_concatenated(const std::vector<std::vector<uint8_t>>& parts) {
    std::vector<uint8_t> buf;
    std::size_t total = 0;
    for (const auto& p : parts) {
        total += p.size();
    }
    buf.reserve(total);
    for (const auto& p : parts) {
        buf.insert(buf.end(), p.begin(), p.end());
    }
    return blake3_hash(buf);
}

}  // namespace

Transcript generate_transcript(
    const std::vector<uint8_t>& nonce,
    const std::vector<std::vector<uint8_t>>& eval_keys,
    const std::vector<std::vector<uint8_t>>& input_cts,
    const std::vector<uint8_t>& output_ct) {
    Transcript t;
    t.nonce = nonce;
    t.eval_key_hash = hash_concatenated(eval_keys);

    t.input_ct_hashes.clear();
    t.input_ct_hashes.reserve(input_cts.size());
    for (const auto& ct : input_cts) {
        t.input_ct_hashes.push_back(blake3_hash(ct));
    }

    t.output_ct_hash = blake3_hash(output_ct);
    return t;
}

std::array<uint8_t, 32> compute_transcript_hash(const Transcript& transcript) {
    Transcript t_for_hash = transcript;
    t_for_hash.fhe_eval_us = 0;
    t_for_hash.transcript_us = 0;
    t_for_hash.quote_us = 0;
    std::string json_str = t_for_hash.to_json();
    Hash32 h = blake3_hash(json_str);
    std::array<uint8_t, 32> out{};
    std::memcpy(out.data(), h.data(), 32);
    return out;
}

std::vector<uint8_t> generate_tdx_quote(
    const std::array<uint8_t, 32>& transcript_hash) {
    tdx_report_data_t report_data{};
    std::memset(&report_data, 0, sizeof(report_data));
    std::memcpy(report_data.d, transcript_hash.data(), 32);

    tdx_uuid_t key_id{};
    uint8_t* quote_buf = nullptr;
    uint32_t quote_size = 0;

    tdx_attest_error_t rc = tdx_att_get_quote(
        &report_data, nullptr, 0, &key_id, &quote_buf, &quote_size, 0);
    if (rc != TDX_ATTEST_SUCCESS) {
        throw std::runtime_error(
            std::string("[attestation] tdx_att_get_quote failed (code ") +
            std::to_string(rc) + ")");
    }

    std::vector<uint8_t> quote(quote_buf, quote_buf + quote_size);
    tdx_att_free_quote(quote_buf);
    return quote;
}

std::array<uint8_t, 32> compute_gpu_evidence_digest(
    const std::vector<uint8_t>& gpu_evidence_serialized) {
    Hash32 h = blake3_hash(gpu_evidence_serialized);
    std::array<uint8_t, 32> out{};
    std::memcpy(out.data(), h.data(), 32);
    return out;
}

std::array<uint8_t, 32> compute_heterogeneous_binding_digest(
    const std::array<uint8_t, 32>& transcript_digest,
    const std::array<uint8_t, 32>& gpu_evidence_digest) {
    std::vector<uint8_t> buf(64);
    std::memcpy(buf.data(), transcript_digest.data(), 32);
    std::memcpy(buf.data() + 32, gpu_evidence_digest.data(), 32);
    Hash32 h = blake3_hash(buf);
    std::array<uint8_t, 32> out{};
    std::memcpy(out.data(), h.data(), 32);
    return out;
}

std::vector<uint8_t> generate_tdx_quote_heterogeneous(
    const std::array<uint8_t, 32>& transcript_digest,
    const std::array<uint8_t, 32>& gpu_evidence_digest) {

    auto binding = compute_heterogeneous_binding_digest(transcript_digest, gpu_evidence_digest);

    tdx_report_data_t report_data{};
    std::memset(&report_data, 0, sizeof(report_data));
    std::memcpy(report_data.d, binding.data(), 32);

    tdx_uuid_t key_id{};
    uint8_t* quote_buf = nullptr;
    uint32_t quote_size = 0;

    tdx_attest_error_t rc = tdx_att_get_quote(
        &report_data, nullptr, 0, &key_id, &quote_buf, &quote_size, 0);
    if (rc != TDX_ATTEST_SUCCESS) {
        throw std::runtime_error(
            std::string("[attestation] heterogeneous quote failed (code ") +
            std::to_string(rc) + ")");
    }

    std::vector<uint8_t> quote(quote_buf, quote_buf + quote_size);
    tdx_att_free_quote(quote_buf);
    return quote;
}

}  // namespace tee
