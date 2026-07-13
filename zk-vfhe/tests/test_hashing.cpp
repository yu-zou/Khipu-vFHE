#include <gtest/gtest.h>
#include "common/hashing.h"
#include <array>
#include <cstdint>
#include <string>
#include <vector>
using namespace zk;

TEST(Hashing, Blake3Empty) {
    auto h = blake3_hash(std::vector<uint8_t>{});
    std::array<uint8_t,32> expected = {
        0xaf,0x13,0x49,0xb9,0xf5,0xf9,0xa1,0xa6,0xa0,0x40,0x4d,0xea,0x36,0xdc,0xc9,0x49,
        0x9b,0xcb,0x25,0xc9,0xad,0xc1,0x12,0xb7,0xcc,0x9a,0x93,0xca,0xe4,0x1f,0x32,0x62
    };
    EXPECT_EQ(h, expected);
}

TEST(Hashing, Blake3Test) {
    auto h = blake3_hash(std::vector<uint8_t>{'t','e','s','t'});
    std::array<uint8_t,32> expected = {
        0x48,0x78,0xca,0x04,0x25,0xc7,0x39,0xfa,0x42,0x7f,0x7e,0xda,0x20,0xfe,0x84,0x5f,
        0x6b,0x2e,0x46,0xba,0x5f,0xe2,0xa1,0x4d,0xf5,0xb1,0xe3,0x2f,0x50,0x60,0x32,0x15
    };
    EXPECT_EQ(h, expected);
}

TEST(Hashing, HexRoundTrip) {
    std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
    std::string hex = to_hex(data);
    EXPECT_EQ(hex, "deadbeef");
    auto bytes = from_hex(hex);
    EXPECT_EQ(bytes, data);
}

TEST(Hashing, Hash32HexRoundTrip) {
    auto h = blake3_hash(std::string("hello"));
    std::string hex = to_hex(h);
    EXPECT_EQ(hex.size(), 64u);
    Hash32 h2 = hash_from_hex(hex);
    EXPECT_EQ(h, h2);
}

TEST(Hashing, FromHexOddLengthThrows) {
    EXPECT_THROW(from_hex("abc"), std::invalid_argument);
}

TEST(Hashing, HashFromHexWrongLengthThrows) {
    EXPECT_THROW(hash_from_hex("abcd"), std::invalid_argument);
}

TEST(Hashing, StringHashMatchesVectorHash) {
    std::string s = "test";
    std::vector<uint8_t> v(s.begin(), s.end());
    auto h1 = blake3_hash(s);
    auto h2 = blake3_hash(v);
    EXPECT_EQ(h1, h2);
}
