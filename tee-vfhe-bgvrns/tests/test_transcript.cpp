#include <gtest/gtest.h>
#include "common/transcript.h"
#include "common/serialization.h"
#include "common/hashing.h"
#include "common/attestation.h"
#include "openfhe.h"
using namespace tee;
using namespace lbcrypto;

TEST(Transcript, RoundTripAndHash) {
    Transcript t;
    t.nonce = {1,2,3,4};
    t.eval_key_hash = blake3_hash(std::vector<uint8_t>{5,6,7,8});
    t.input_ct_hashes.push_back(blake3_hash(std::vector<uint8_t>{9,10}));
    t.output_ct_hash = blake3_hash(std::vector<uint8_t>{11,12});
    t.fhe_eval_us = 100;
    t.transcript_us = 200;
    t.quote_us = 300;
    auto j = t.to_json();
    auto t2 = Transcript::from_json(j);
    EXPECT_EQ(t.nonce, t2.nonce);
    EXPECT_EQ(t.eval_key_hash, t2.eval_key_hash);
    EXPECT_EQ(t.input_ct_hashes, t2.input_ct_hashes);
    EXPECT_EQ(t.output_ct_hash, t2.output_ct_hash);
    EXPECT_EQ(compute_transcript_hash(t), compute_transcript_hash(t2));
}

TEST(Serialization, BGVCiphertextRoundTrip) {
    CCParams<CryptoContextBGVRNS> p;
    p.SetMultiplicativeDepth(2);
    p.SetPlaintextModulus(65537);
    p.SetBatchSize(8);
    p.SetSecurityLevel(HEStd_128_classic);
    p.SetKeySwitchTechnique(BV);
    p.SetDigitSize(4);
    p.SetScalingTechnique(FIXEDMANUAL);
    p.SetFirstModSize(60);
    auto cc = GenCryptoContext(p);
    cc->Enable(PKE); cc->Enable(KEYSWITCH); cc->Enable(LEVELEDSHE);
    auto kp = cc->KeyGen();
    std::vector<int64_t> vals = {1,2,3,4,5,6,7,8};
    auto pt = cc->MakePackedPlaintext(vals);
    auto ct = cc->Encrypt(kp.publicKey, pt);
    std::string s = serialize_ciphertext(ct);
    auto ct2 = deserialize_ciphertext(s);
    Plaintext pt2;
    cc->Decrypt(kp.secretKey, ct2, &pt2);
    pt2->SetLength(8);
    EXPECT_EQ(pt2->GetPackedValue(), vals);
}
