#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

#include "common/attestation.h"
#include "common/hashing.h"
#include "common/transcript.h"

using namespace tee;

TEST(Attestation, TranscriptAndHash) {
    std::vector<uint8_t> nonce{0xAA, 0xBB, 0xCC, 0xDD};
    std::vector<std::vector<uint8_t>> eval_keys{
        std::vector<uint8_t>{0x01, 0x02},
        std::vector<uint8_t>{0x03, 0x04},
    };
    std::vector<std::vector<uint8_t>> input_cts{
        std::vector<uint8_t>{0x10, 0x20, 0x30},
        std::vector<uint8_t>{0x40, 0x50},
    };
    std::vector<uint8_t> output_ct{0x60, 0x70, 0x80, 0x90};

    Transcript t = generate_transcript(nonce, eval_keys, input_cts, output_ct);

    EXPECT_EQ(t.nonce, nonce);

    std::vector<uint8_t> eval_concat;
    eval_concat.reserve(4);
    eval_concat.insert(eval_concat.end(), eval_keys[0].begin(), eval_keys[0].end());
    eval_concat.insert(eval_concat.end(), eval_keys[1].begin(), eval_keys[1].end());
    EXPECT_EQ(t.eval_key_hash, blake3_hash(eval_concat));

    ASSERT_EQ(t.input_ct_hashes.size(), input_cts.size());
    for (std::size_t i = 0; i < input_cts.size(); ++i) {
        EXPECT_EQ(t.input_ct_hashes[i], blake3_hash(input_cts[i]))
            << "input_ct_hashes mismatch at index " << i;
    }

    EXPECT_EQ(t.output_ct_hash, blake3_hash(output_ct));

    std::array<uint8_t, 32> hash = compute_transcript_hash(t);
    bool any_nonzero = std::any_of(hash.begin(), hash.end(),
                                   [](uint8_t b) { return b != 0; });
    EXPECT_TRUE(any_nonzero);
}

TEST(Attestation, TDXQuoteNonEmpty) {
    std::vector<uint8_t> sample{0xDE, 0xAD, 0xBE, 0xEF};
    std::array<uint8_t, 32> hash = blake3_hash(sample);

    std::vector<uint8_t> quote = generate_tdx_quote(hash);
    EXPECT_GT(quote.size(), 0u);
    EXPECT_LT(quote.size(), 100000u);
}
