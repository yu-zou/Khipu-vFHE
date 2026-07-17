// Google Test unit tests for Transcript JSON serialization and hex encoding.
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "common/hashing.h"
#include "common/transcript.h"

using namespace tee;

// Build a Transcript, serialize to JSON, deserialize, and compare all fields.
TEST(Transcript, JsonRoundTrip) {
    Transcript original;
    original.nonce = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04};
    original.eval_key_hash = blake3_hash("eval_key_data");
    original.input_ct_hashes.push_back(blake3_hash("input_ct_1"));
    original.input_ct_hashes.push_back(blake3_hash("input_ct_2"));
    original.output_ct_hash = blake3_hash("output_ct");

    std::string json_str = original.to_json();
    ASSERT_FALSE(json_str.empty());
    EXPECT_NE(json_str.find("nonce"), std::string::npos);
    EXPECT_NE(json_str.find("eval_key_hash"), std::string::npos);
    EXPECT_NE(json_str.find("input_ct_hashes"), std::string::npos);
    EXPECT_NE(json_str.find("output_ct_hash"), std::string::npos);

    Transcript restored = Transcript::from_json(json_str);

    EXPECT_EQ(original.nonce, restored.nonce);
    EXPECT_EQ(original.eval_key_hash, restored.eval_key_hash);
    ASSERT_EQ(original.input_ct_hashes.size(), restored.input_ct_hashes.size());
    for (size_t i = 0; i < original.input_ct_hashes.size(); ++i) {
        EXPECT_EQ(original.input_ct_hashes[i], restored.input_ct_hashes[i]);
    }
    EXPECT_EQ(original.output_ct_hash, restored.output_ct_hash);
}

// Verify to_hex of a nonce produces expected lowercase hex.
TEST(Transcript, HexEncoding) {
    std::vector<uint8_t> nonce = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04};
    EXPECT_EQ(to_hex(nonce), "deadbeef01020304");

    // Single-byte edge cases.
    std::vector<uint8_t> single = {0x00};
    EXPECT_EQ(to_hex(single), "00");

    std::vector<uint8_t> high = {0xFF};
    EXPECT_EQ(to_hex(high), "ff");

    // Multi-byte with mixed high/low nibbles.
    std::vector<uint8_t> mixed = {0x0A, 0x10, 0xF0, 0x5C};
    EXPECT_EQ(to_hex(mixed), "0a10f05c");
}
