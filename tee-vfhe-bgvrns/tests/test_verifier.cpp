#include <gtest/gtest.h>

#include "client/verifier.h"
#include "common/attestation.h"
#include "common/hashing.h"
#include "common/transcript.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

using namespace tee;

namespace {

// Build the expected report_data_hex the same way Verifier::verify_all does:
// 64 zero hex chars (the zeroed second half of the 64-byte report data field,
// which the DCAP library surfaces first after byte-reversal) followed by the
// 32-byte transcript hash reversed and hex-encoded (64 chars) -> 128 chars.
std::string build_report_data_hex(const Hash32& transcript_hash) {
    std::string hash_hex = to_hex(transcript_hash);
    std::string hash_hex_rev;
    for (int i = static_cast<int>(hash_hex.size()) - 2; i >= 0; i -= 2) {
        hash_hex_rev += hash_hex.substr(i, 2);
    }
    std::string report_data_hex(64, '0');
    report_data_hex += hash_hex_rev;
    return report_data_hex;
}

}  // namespace

TEST(Verifier, TranscriptValidAndInvalid) {
    std::vector<uint8_t> nonce = {1, 2, 3, 4};
    std::vector<std::vector<uint8_t>> eval_keys = {{10, 20, 30}};
    std::vector<std::vector<uint8_t>> input_cts = {
        {100, 101, 102},
        {200, 201, 202, 203},
    };
    std::vector<uint8_t> output_ct = {5, 6, 7, 8, 9};

    Transcript t = generate_transcript(nonce, eval_keys, input_cts, output_ct);

    Verifier v;
    EXPECT_TRUE(v.verify_transcript(t, nonce, t.eval_key_hash,
                                    t.input_ct_hashes, t.output_ct_hash));

    // Wrong nonce must fail.
    std::vector<uint8_t> wrong_nonce = {9, 9, 9, 9};
    EXPECT_FALSE(v.verify_transcript(t, wrong_nonce, t.eval_key_hash,
                                     t.input_ct_hashes, t.output_ct_hash));
}

TEST(Verifier, RealQuoteVerification) {
    std::vector<uint8_t> nonce = {1, 2, 3, 4};
    std::vector<std::vector<uint8_t>> eval_keys = {{10, 20, 30}};
    std::vector<std::vector<uint8_t>> input_cts = {
        {100, 101, 102},
        {200, 201, 202, 203},
    };
    std::vector<uint8_t> output_ct = {5, 6, 7, 8, 9};

    Transcript t = generate_transcript(nonce, eval_keys, input_cts, output_ct);

    auto transcript_hash = compute_transcript_hash(t);
    std::string report_data_hex = build_report_data_hex(transcript_hash);

    // Generate a real TDX quote bound to the transcript hash.
    std::vector<uint8_t> quote = generate_tdx_quote(transcript_hash);
    ASSERT_FALSE(quote.empty());

    Verifier v;
    EXPECT_TRUE(v.verify_tdx_quote(quote, "", report_data_hex));
    EXPECT_TRUE(v.verify_all(quote, t, nonce, "", t.eval_key_hash,
                             t.input_ct_hashes, t.output_ct_hash));
}
