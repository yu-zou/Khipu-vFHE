#include <gtest/gtest.h>

#include <array>
#include <vector>
#include <string>

#include "client/verifier.h"
#include "common/attestation.h"
#include "common/hashing.h"
#include "common/transcript.h"

using namespace tee;

TEST(Verifier, VerifyTranscript) {
    Transcript t;
    t.nonce = {1, 2, 3, 4};
    t.eval_key_hash = blake3_hash("eval-key");
    t.input_ct_hashes.push_back(blake3_hash("input-1"));
    t.input_ct_hashes.push_back(blake3_hash("input-2"));
    t.output_ct_hash = blake3_hash("output");

    Verifier v;

    EXPECT_TRUE(v.verify_transcript(
        t,
        {1, 2, 3, 4},
        blake3_hash("eval-key"),
        {blake3_hash("input-1"), blake3_hash("input-2")},
        blake3_hash("output")));

    EXPECT_FALSE(v.verify_transcript(
        t,
        {9, 9, 9},
        blake3_hash("eval-key"),
        {blake3_hash("input-1"), blake3_hash("input-2")},
        blake3_hash("output")));

    EXPECT_FALSE(v.verify_transcript(
        t,
        {1, 2, 3, 4},
        blake3_hash("wrong-key"),
        {blake3_hash("input-1"), blake3_hash("input-2")},
        blake3_hash("output")));

    EXPECT_FALSE(v.verify_transcript(
        t,
        {1, 2, 3, 4},
        blake3_hash("eval-key"),
        {blake3_hash("input-1")},
        blake3_hash("output")));

    EXPECT_FALSE(v.verify_transcript(
        t,
        {1, 2, 3, 4},
        blake3_hash("eval-key"),
        {blake3_hash("input-1"), blake3_hash("input-2")},
        blake3_hash("wrong-output")));
}

TEST(Verifier, VerifyTDXQuoteReal) {
    std::array<uint8_t, 32> dummy{};
    for (std::size_t i = 0; i < dummy.size(); ++i) dummy[i] = static_cast<uint8_t>(i);
    std::vector<uint8_t> quote;
    try {
        quote = generate_tdx_quote(dummy);
    } catch (const std::runtime_error&) {
        GTEST_SKIP() << "TDX quote generation not available; skipping real quote test.";
    }
    std::string report_data_hex = to_hex(dummy);
    // The DCAP library reports the report_data with the hash in the
    // last 32 bytes (64 hex chars) and the hash bytes in reverse order.
    std::string hash_rev;
    for (int i = static_cast<int>(report_data_hex.size()) - 2; i >= 0; i -= 2) {
        hash_rev += report_data_hex.substr(i, 2);
    }
    std::string expected(64, '0');
    expected += hash_rev;
    Verifier v;
    bool ok = v.verify_tdx_quote(quote, "", expected);
    EXPECT_TRUE(ok);
}

TEST(Verifier, VerifyAllLocalBadQuote) {
    Transcript t;
    t.nonce = {1, 2, 3};
    t.eval_key_hash = blake3_hash("ek");
    t.input_ct_hashes.push_back(blake3_hash("in1"));
    t.output_ct_hash = blake3_hash("out");

    std::vector<uint8_t> bad_quote = {0x00, 0x01, 0x02, 0x03};
    Verifier v;

    bool ok1 = v.verify_all(
        bad_quote, t,
        {1, 2, 3},
        "",
        blake3_hash("ek"),
        {blake3_hash("in1")},
        blake3_hash("out"));
    EXPECT_FALSE(ok1);

    bool ok2 = v.verify_all(
        bad_quote, t,
        {9, 9, 9},
        "",
        blake3_hash("ek"),
        {blake3_hash("in1")},
        blake3_hash("out"));
    EXPECT_FALSE(ok2);
}
