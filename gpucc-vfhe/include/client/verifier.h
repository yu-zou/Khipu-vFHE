#pragma once

#include <string>
#include <vector>

#include "common/transcript.h"
#include "common/h100_evidence_adapter.h"

namespace tee {

class Verifier {
public:
    bool verify_tdx_quote(const std::vector<uint8_t>& quote_bytes,
                          const std::string& expected_mr_td_hex,
                          const std::string& expected_report_data_hex);

    bool verify_transcript(const Transcript& transcript,
                           const std::vector<uint8_t>& expected_nonce,
                           const Hash32& expected_eval_key_hash,
                           const std::vector<Hash32>& expected_input_ct_hashes,
                           const Hash32& expected_output_ct_hash);

    bool verify_all(const std::vector<uint8_t>& quote_bytes,
                    const Transcript& transcript,
                    const std::vector<uint8_t>& expected_nonce,
                    const std::string& expected_mr_td_hex,
                    const Hash32& expected_eval_key_hash,
                    const std::vector<Hash32>& expected_input_ct_hashes,
                    const Hash32& expected_output_ct_hash);

    bool verify_gpu_evidence(const std::vector<uint8_t>& gpu_evidence_serialized,
                             const std::vector<uint8_t>& expected_nonce);

    bool verify_heterogeneous(const std::vector<uint8_t>& quote_bytes,
                              const std::vector<uint8_t>& gpu_evidence_serialized,
                              const Transcript& transcript,
                              const std::vector<uint8_t>& expected_nonce,
                              const std::string& expected_mr_td_hex,
                              const Hash32& expected_eval_key_hash,
                              const std::vector<Hash32>& expected_input_ct_hashes,
                              const Hash32& expected_output_ct_hash);
};

}  // namespace tee
