#include "client/verifier.h"

#include <openssl/evp.h>

#include <sgx_dcap_quoteverify.h>
#include <sgx_dcap_qal.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>

#include <nlohmann/json.hpp>

#include "common/attestation.h"
#include "common/hashing.h"

namespace tee {

namespace {

using json = nlohmann::json;

static std::vector<uint8_t> b64_decode(const std::string& in) {
    std::string s = in;
    while (s.size() % 4 != 0) s.push_back('=');
    std::vector<uint8_t> out(s.size());
    int n = EVP_DecodeBlock(out.data(),
                            reinterpret_cast<const unsigned char*>(s.data()),
                            static_cast<int>(s.size()));
    if (n < 0) throw std::runtime_error("base64 decode failed");
    std::size_t pad = 0;
    if (!s.empty() && s[s.size() - 1] == '=') pad++;
    if (s.size() >= 2 && s[s.size() - 2] == '=') pad++;
    std::size_t final_len = static_cast<std::size_t>(n) - pad;
    out.resize(final_len);
    return out;
}

static std::vector<uint8_t> base64url_decode(const std::string& in) {
    std::string s = in;
    for (char& c : s) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    return b64_decode(s);
}

static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

static bool hex_match(const std::string& a, const std::string& b) { return to_lower(a) == to_lower(b); }

} // namespace
bool Verifier::verify_tdx_quote(const std::vector<uint8_t>& quote_bytes,
                                const std::string& expected_mr_td_hex,
                                const std::string& expected_report_data_hex) {
    try {
        // Use the DCAP library to verify the TDX quote locally.
        // This uses the Alibaba Cloud PCCS for certificate collateral
        // (same infrastructure as the remote attestation API).
        uint32_t jwt_size = 0;
        uint8_t* jwt_buf = nullptr;

        quote3_error_t ret = tee_verify_quote_qvt(
            quote_bytes.data(), static_cast<uint32_t>(quote_bytes.size()),
            nullptr,   // p_quote_collateral — use PCCS
            nullptr,   // p_qve_report_info
            nullptr,   // p_user_data
            &jwt_size,
            &jwt_buf);

        if (ret != SGX_QL_SUCCESS) {
            std::cerr << "[verifier] tee_verify_quote_qvt failed: 0x"
                      << std::hex << ret << std::dec << std::endl;
            return false;
        }

        // Appraise the verification token to get the full appraisal
        // result including the TD report data (tdx_reportdata, tdx_mrtd).
        uint32_t appr_size = 0;
        uint8_t* appr_buf = nullptr;
        time_t now = std::time(nullptr);

        // Read the default tenant TD policy (same as Alibaba's sample).
        // The policy is required for tee_appraise_verification_token to
        // produce the full appraisal result including report_data.
        std::ifstream policy_file("/opt/alibaba/tdx-quote-verification-sample/Policies/tenant_td_policy.jwt",
                                  std::ios::binary);
        if (!policy_file) {
            std::cerr << "[verifier] cannot open TD policy file" << std::endl;
            tee_free_verify_quote_qvt(jwt_buf, &jwt_size);
            return false;
        }
        std::vector<uint8_t> policy_data(
            (std::istreambuf_iterator<char>(policy_file)),
            std::istreambuf_iterator<char>());
        policy_data.push_back('\0');
        uint8_t* policies[] = {policy_data.data()};

        quote3_error_t appr_ret = tee_appraise_verification_token(
            jwt_buf, policies, 1, now, nullptr, &appr_size, &appr_buf);

        // Free the verification token (no longer needed).
        tee_free_verify_quote_qvt(jwt_buf, &jwt_size);

        if (appr_ret != SGX_QL_SUCCESS) {
            std::cerr << "[verifier] tee_appraise_verification_token failed: 0x"
                      << std::hex << appr_ret << std::dec << std::endl;
            return false;
        }

        // Parse the appraisal result token (JWT, alg=none).
        std::string jwt_str(reinterpret_cast<char*>(appr_buf), appr_size);
        tee_free_appraisal_token(appr_buf);

        auto dot1 = jwt_str.find('.');
        auto dot2 = jwt_str.find('.', dot1 + 1);
        if (dot1 == std::string::npos || dot2 == std::string::npos) {
            std::cerr << "[verifier] malformed JWT from DCAP" << std::endl;
            return false;
        }
        std::string payload_b64 = jwt_str.substr(dot1 + 1, dot2 - dot1 - 1);
        auto payload_bytes = base64url_decode(payload_b64);
        json payload = json::parse(
            std::string(payload_bytes.begin(), payload_bytes.end()));

        // The appraisal_result field is a JSON string containing the
        // verification results array. Parse it.
        std::string appraisal_str = payload.value("appraisal_result", "");
        if (appraisal_str.empty()) {
            std::cerr << "[verifier] appraisal_result not found in JWT"
                      << std::endl;
            return false;
        }
        json appraisal = json::parse(appraisal_str);

        // Find the TD report in the appraised_reports array by looking
        // for the entry that contains tdx_reportdata in its measurement.
        const auto& reports = appraisal[0]["result"]["appraised_reports"];
        json meas;
        bool found = false;
        for (const auto& rep : reports) {
            if (rep.contains("report") &&
                rep["report"].contains("measurement") &&
                rep["report"]["measurement"].contains("tdx_reportdata")) {
                meas = rep["report"]["measurement"];
                found = true;
                break;
            }
        }
        if (!found) {
            std::cerr << "[verifier] tdx_reportdata not found in DCAP JWT"
                      << std::endl;
            return false;
        }

        std::string report_data_hex = meas.value("tdx_reportdata", "");
        if (report_data_hex.empty()) {
            std::cerr << "[verifier] tdx_reportdata not found in DCAP JWT"
                      << std::endl;
            return false;
        }

        if (!hex_match(report_data_hex, expected_report_data_hex)) {
            std::cerr << "[verifier] report_data mismatch: got="
                      << report_data_hex
                      << " expected=" << expected_report_data_hex << std::endl;
            return false;
        }

        if (!expected_mr_td_hex.empty()) {
            std::string mr_td_hex = meas.value("tdx_mrtd", "");
            if (mr_td_hex.empty()) {
                std::cerr << "[verifier] tdx_mrtd not found in DCAP JWT"
                          << std::endl;
                return false;
            }
            if (!hex_match(mr_td_hex, expected_mr_td_hex)) {
                std::cerr << "[verifier] mr_td mismatch: got=" << mr_td_hex
                          << " expected=" << expected_mr_td_hex << std::endl;
                return false;
            }
        }

        return true;
    } catch (const std::exception& e) {
        std::cerr << "[verifier] verify_tdx_quote failed: " << e.what()
                  << std::endl;
        return false;
    }
}

bool Verifier::verify_transcript(const Transcript& transcript,
                                 const std::vector<uint8_t>& expected_nonce,
                                 const Hash32& expected_eval_key_hash,
                                 const std::vector<Hash32>& expected_input_ct_hashes,
                                 const Hash32& expected_output_ct_hash) {
    if (transcript.nonce != expected_nonce) return false;
    if (transcript.eval_key_hash != expected_eval_key_hash) return false;
    if (transcript.input_ct_hashes.size() != expected_input_ct_hashes.size()) return false;
    for (std::size_t i = 0; i < transcript.input_ct_hashes.size(); ++i) {
        if (transcript.input_ct_hashes[i] != expected_input_ct_hashes[i]) return false;
    }
    if (transcript.output_ct_hash != expected_output_ct_hash) return false;
    return true;
}

bool Verifier::verify_all(const std::vector<uint8_t>& quote_bytes,
                          const Transcript& transcript,
                          const std::vector<uint8_t>& expected_nonce,
                          const std::string& expected_mr_td_hex,
                          const Hash32& expected_eval_key_hash,
                          const std::vector<Hash32>& expected_input_ct_hashes,
                          const Hash32& expected_output_ct_hash) {
    auto h = compute_transcript_hash(transcript);
    // The DCAP library reports the report_data as 128 hex chars with
    // the hash in the last 32 bytes (64 hex chars) and the hash bytes
    // in reverse order.
    std::string hash_hex = to_hex(h);
    std::string hash_hex_rev;
    for (int i = static_cast<int>(hash_hex.size()) - 2; i >= 0; i -= 2) {
        hash_hex_rev += hash_hex.substr(i, 2);
    }
    std::string expected_report_data_hex(64, '0');
    expected_report_data_hex += hash_hex_rev;

    bool t_ok = verify_transcript(transcript, expected_nonce, expected_eval_key_hash,
                                  expected_input_ct_hashes, expected_output_ct_hash);
    if (!t_ok) return false;

    bool q_ok = verify_tdx_quote(quote_bytes, expected_mr_td_hex, expected_report_data_hex);
    return q_ok;
}

}  // namespace tee
