#include <gtest/gtest.h>

#include <array>
#include <vector>

#include "common/attestation.h"
#include "common/hashing.h"
#include "common/transcript.h"

using namespace tee;

TEST(Attestation, GenerateTranscript) {
    std::vector<uint8_t> nonce = {1, 2, 3};
    std::vector<std::vector<uint8_t>> eval_keys = {{4, 5}, {6, 7}};
    std::vector<std::vector<uint8_t>> input_cts = {{8, 9}, {10, 11}};
    std::vector<uint8_t> output_ct = {12, 13};

    Transcript t = generate_transcript(nonce, eval_keys, input_cts, output_ct);

    EXPECT_EQ(t.nonce, nonce);
    EXPECT_EQ(t.input_ct_hashes.size(), input_cts.size());
    for (const auto& h : t.input_ct_hashes) {
        EXPECT_EQ(h.size(), 32u);
    }
    EXPECT_EQ(t.eval_key_hash.size(), 32u);
    EXPECT_EQ(t.output_ct_hash.size(), 32u);

    Hash32 expected_eval = blake3_hash(std::vector<uint8_t>{4, 5, 6, 7});
    EXPECT_EQ(t.eval_key_hash, expected_eval);
    EXPECT_EQ(t.input_ct_hashes[0], blake3_hash(std::vector<uint8_t>{8, 9}));
    EXPECT_EQ(t.input_ct_hashes[1], blake3_hash(std::vector<uint8_t>{10, 11}));
    EXPECT_EQ(t.output_ct_hash, blake3_hash(std::vector<uint8_t>{12, 13}));
}

TEST(Attestation, ComputeTranscriptHash) {
    Transcript t;
    t.nonce = {1, 2, 3};
    t.eval_key_hash = blake3_hash("ek");
    t.input_ct_hashes.push_back(blake3_hash("in1"));
    t.input_ct_hashes.push_back(blake3_hash("in2"));
    t.output_ct_hash = blake3_hash("out");

    auto h1 = compute_transcript_hash(t);
    auto h2 = compute_transcript_hash(t);
    EXPECT_EQ(h1.size(), 32u);
    EXPECT_EQ(h1, h2);

    Transcript t2 = t;
    t2.nonce.push_back(99);
    auto h3 = compute_transcript_hash(t2);
    EXPECT_NE(h1, h3);
}

TEST(Attestation, GenerateTDXQuote) {
    std::array<uint8_t, 32> dummy{};
    for (std::size_t i = 0; i < dummy.size(); ++i) {
        dummy[i] = static_cast<uint8_t>(i);
    }

    try {
        auto quote = generate_tdx_quote(dummy);
        EXPECT_GT(quote.size(), 0u);
        EXPECT_LT(quote.size(), 100u * 1024u);
    } catch (const std::runtime_error&) {
        // Not running inside a TDX guest — graceful skip.
        GTEST_SKIP() << "TDX quote generation not available in this environment; skipping.";
    }
}
