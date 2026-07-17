// Google Test unit tests for Blake3 hashing (KAT and determinism).
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "common/hashing.h"

using namespace tee;

// Blake3("") official test vector.
TEST(Hashing, Blake3Empty) {
    auto h = blake3_hash(std::string(""));
    EXPECT_EQ(to_hex(h),
              "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
}

// Blake3("test") known-answer vector.
TEST(Hashing, Blake3Test) {
    auto h = blake3_hash("test");
    EXPECT_EQ(to_hex(h),
              "4878ca0425c739fa427f7eda20fe845f6b2e46ba5fe2a14df5b1e32f50603215");
}

// Same input always produces the same hash; different inputs differ.
TEST(Hashing, Determinism) {
    std::string input = "deterministic input for blake3";
    auto h1 = blake3_hash(input);
    auto h2 = blake3_hash(input);
    EXPECT_EQ(h1, h2);

    // All three overloads should agree on the same bytes.
    std::vector<uint8_t> vec_input(input.begin(), input.end());
    auto h3 = blake3_hash(vec_input);
    EXPECT_EQ(h1, h3);

    auto h4 = blake3_hash(vec_input.data(), vec_input.size());
    EXPECT_EQ(h1, h4);

    // Different inputs must produce different hashes.
    auto h_other = blake3_hash("different input");
    EXPECT_NE(h1, h_other);

    // Empty vector and empty string must match.
    auto h_empty_str = blake3_hash(std::string(""));
    auto h_empty_vec = blake3_hash(std::vector<uint8_t>{});
    EXPECT_EQ(h_empty_str, h_empty_vec);
}
