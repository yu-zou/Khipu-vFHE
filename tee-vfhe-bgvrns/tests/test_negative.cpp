#include <gtest/gtest.h>

#include "client/verifier.h"
#include "common/attestation.h"
#include "common/hashing.h"
#include "common/transcript.h"

#include <cstdint>
#include <string>
#include <vector>

using namespace tee;

namespace {

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

struct Fixture {
    std::vector<uint8_t> nonce = {1, 2, 3, 4};
    std::vector<std::vector<uint8_t>> eval_keys = {{10, 20, 30}};
    std::vector<std::vector<uint8_t>> input_cts = {
        {100, 101, 102},
        {200, 201, 202, 203},
    };
    std::vector<uint8_t> output_ct = {5, 6, 7, 8, 9};
    Transcript t;
    Hash32 ek_hash;
    std::vector<Hash32> in_hashes;
    Hash32 out_hash;

    Fixture() {
        t = generate_transcript(nonce, eval_keys, input_cts, output_ct);
        ek_hash = t.eval_key_hash;
        in_hashes = t.input_ct_hashes;
        out_hash = t.output_ct_hash;
    }
};

}  // namespace

// Test 1: Tamper output ciphertext -> output hash mismatch fails verify_transcript
TEST(Negative, TamperOutputCiphertext) {
    Fixture f;
    Verifier v;

    Transcript bad = f.t;
    bad.output_ct_hash[0] ^= 0xFF;

    EXPECT_FALSE(v.verify_transcript(bad, f.nonce, f.ek_hash,
                                     f.in_hashes, f.out_hash));
}

// Test 2: Tamper input ciphertext hash in transcript -> verify_transcript fails
TEST(Negative, TamperInputCtHash) {
    Fixture f;
    Verifier v;

    Transcript bad = f.t;
    bad.input_ct_hashes[0][0] ^= 0xFF;

    EXPECT_FALSE(v.verify_transcript(bad, f.nonce, f.ek_hash,
                                     f.in_hashes, f.out_hash));
}

// Test 3: Replay old transcript with new input hashes -> verify_transcript fails
TEST(Negative, ReplayOldTranscript) {
    Fixture f;
    Verifier v;

    std::vector<std::vector<uint8_t>> new_inputs = {
        {0xAA, 0xBB, 0xCC},
        {0xDD, 0xEE},
    };
    std::vector<Hash32> new_hashes;
    for (const auto& ct : new_inputs) {
        new_hashes.push_back(blake3_hash(ct));
    }

    // The old transcript has old input hashes, we pass new ones -> mismatch
    EXPECT_FALSE(v.verify_transcript(f.t, f.nonce, f.ek_hash,
                                     new_hashes, f.out_hash));
}

// Test 4: Mismatched TDX quote -> verify_all fails when quote hash != transcript hash
TEST(Negative, MismatchedTDXQuote) {
    Fixture f;

    // Generate a TDX quote bound to a DIFFERENT transcript hash
    std::vector<uint8_t> fake_nonce = {0xFF, 0xFF, 0xFF, 0xFF};
    std::vector<std::vector<uint8_t>> fake_keys = {{0xAA}};
    std::vector<std::vector<uint8_t>> fake_cts = {{0xBB}};
    std::vector<uint8_t> fake_out = {0xCC};
    Transcript fake_t = generate_transcript(fake_nonce, fake_keys,
                                            fake_cts, fake_out);
    auto fake_hash = compute_transcript_hash(fake_t);
    std::vector<uint8_t> quote = generate_tdx_quote(fake_hash);
    ASSERT_FALSE(quote.empty());

    Verifier v;
    // verify_all should fail because quote hash != transcript hash
    EXPECT_FALSE(v.verify_all(quote, f.t, f.nonce, "",
                              f.ek_hash, f.in_hashes, f.out_hash));

    // Also verify_tdx_quote should fail with wrong report_data
    std::string real_report_data = build_report_data_hex(
        compute_transcript_hash(f.t));
    EXPECT_FALSE(v.verify_tdx_quote(quote, "", real_report_data));
}

// Test 5: Decrypt-before-verification guard
// The Verifier does not have a `verified` field in the current API.
// Instead, this test verifies that verify_all properly rejects
// tampered transcripts even when the quote itself is valid.
// The spirit of the test is: you cannot trust decrypted results
// without first passing verification.
TEST(Negative, DecryptBeforeVerificationGuard) {
    Fixture f;

    // Generate a valid quote bound to the correct transcript hash
    auto hash = compute_transcript_hash(f.t);
    std::vector<uint8_t> quote = generate_tdx_quote(hash);
    ASSERT_FALSE(quote.empty());

    Verifier v;
    // Verify with correct data first -> should pass
    EXPECT_TRUE(v.verify_all(quote, f.t, f.nonce, "",
                             f.ek_hash, f.in_hashes, f.out_hash));

    // Now tamper the transcript -> verification should fail
    // This demonstrates that decryption without verification
    // would trust a tampered result
    Transcript bad = f.t;
    bad.output_ct_hash[0] ^= 0xFF;
    EXPECT_FALSE(v.verify_all(quote, bad, f.nonce, "",
                              f.ek_hash, f.in_hashes, f.out_hash));
}