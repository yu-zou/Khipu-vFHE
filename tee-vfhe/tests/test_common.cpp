// Test program for common types: Blake3 KAT, CKKS ciphertext round-trip,
// and Transcript JSON round-trip.

#include <iostream>
#include <string>
#include <vector>

#include "common/hashing.h"
#include "common/transcript.h"
#include "common/serialization.h"

#include "openfhe/pke/openfhe.h"

using namespace tee;

static int failures = 0;

void check(bool condition, const std::string& name) {
    if (condition) {
        std::cout << "  PASS: " << name << std::endl;
    } else {
        std::cout << "  FAIL: " << name << std::endl;
        ++failures;
    }
}

// ── Blake3 known-answer test ──────────────────────────────────────────────
// Blake3("") = af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
// Blake3("test") = 4878ca0425c739fa427f7eda20fe845f6b2e46ba5fe2a14df5b1e32f50603215
void test_blake3_kat() {
    std::cout << "[Blake3 KAT]" << std::endl;

    // Empty string — official test vector.
    auto empty_hash = blake3_hash(std::string(""));
    check(to_hex(empty_hash) ==
              "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
          "Blake3(\"\") matches official vector");

    // "test" — computed from reference implementation.
    auto test_hash = blake3_hash("test");
    check(to_hex(test_hash) ==
              "4878ca0425c739fa427f7eda20fe845f6b2e46ba5fe2a14df5b1e32f50603215",
          "Blake3(\"test\") matches known vector");

    // Determinism: same input → same output.
    auto test_hash2 = blake3_hash(std::string("test"));
    check(test_hash == test_hash2, "Blake3 is deterministic across overloads");
}

// ── OpenFHE ciphertext round-trip test ────────────────────────────────────
void test_ciphertext_roundtrip() {
    std::cout << "[Ciphertext Round-Trip]" << std::endl;

    // Create a CKKS context.
    lbcrypto::CCParams<lbcrypto::CryptoContextCKKSRNS> params;
    params.SetMultiplicativeDepth(2);
    params.SetScalingModSize(50);
    params.SetBatchSize(8);
    auto cc = lbcrypto::GenCryptoContext(params);
    cc->Enable(lbcrypto::PKE);
    cc->Enable(lbcrypto::LEVELEDSHE);

    auto keys = cc->KeyGen();
    auto pk = keys.publicKey;
    auto sk = keys.secretKey;

    // Encrypt a plaintext.
    std::vector<double> vals = {1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0};
    auto pt = cc->MakeCKKSPackedPlaintext(vals);
    auto ct = cc->Encrypt(pk, pt);

    // Serialize ciphertext to binary string.
    std::string ct_bytes = serialize_ciphertext(ct);
    check(!ct_bytes.empty(), "ciphertext serializes to non-empty bytes");

    // Deserialize back.
    auto ct2 = deserialize_ciphertext(ct_bytes);
    check(ct2 != nullptr, "deserialized ciphertext is non-null");

    // Verify by decrypting.
    lbcrypto::Plaintext pt_decrypted;
    cc->Decrypt(sk, ct2, &pt_decrypted);
    pt_decrypted->SetLength(vals.size());
    auto decrypted_vals = pt_decrypted->GetCKKSPackedValue();

    bool match = true;
    for (size_t i = 0; i < vals.size(); ++i) {
        if (std::abs(decrypted_vals[i].real() - vals[i]) > 1e-4) {
            match = false;
            break;
        }
    }
    check(match, "decrypted values match original after round-trip");

    // Also test PublicKey and EvalKey round-trip.
    std::string pk_bytes = serialize_public_key(pk);
    auto pk2 = deserialize_public_key(pk_bytes);
    check(pk2 != nullptr, "public key round-trips");

    std::string sk_bytes = serialize_private_key(sk);
    auto sk2 = deserialize_private_key(sk_bytes);
    check(sk2 != nullptr, "private key round-trips");

    cc->EvalMultKeyGen(sk);
    auto eval_keys = cc->GetEvalMultKeyVector(ct->GetKeyTag());
    if (!eval_keys.empty()) {
        std::string ek_bytes = serialize_eval_key(eval_keys[0]);
        auto ek2 = deserialize_eval_key(ek_bytes);
        check(ek2 != nullptr, "eval key round-trips");
    }
}

// ── Transcript JSON round-trip test ───────────────────────────────────────
void test_transcript_json() {
    std::cout << "[Transcript JSON Round-Trip]" << std::endl;

    Transcript original;
    original.nonce = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04};
    original.eval_key_hash = blake3_hash("eval_key_data");
    original.input_ct_hashes.push_back(blake3_hash("input_ct_1"));
    original.input_ct_hashes.push_back(blake3_hash("input_ct_2"));
    original.output_ct_hash = blake3_hash("output_ct");

    // Serialize to JSON.
    std::string json_str = original.to_json();
    check(!json_str.empty(), "transcript serializes to non-empty JSON");
    check(json_str.find("nonce") != std::string::npos,
          "JSON contains nonce field");
    check(json_str.find("eval_key_hash") != std::string::npos,
          "JSON contains eval_key_hash field");
    check(json_str.find("input_ct_hashes") != std::string::npos,
          "JSON contains input_ct_hashes field");
    check(json_str.find("output_ct_hash") != std::string::npos,
          "JSON contains output_ct_hash field");

    // Deserialize back.
    Transcript restored = Transcript::from_json(json_str);

    check(original.nonce == restored.nonce, "nonce round-trips");
    check(original.eval_key_hash == restored.eval_key_hash,
          "eval_key_hash round-trips");
    check(original.input_ct_hashes.size() ==
              restored.input_ct_hashes.size(),
          "input_ct_hashes count matches");
    check(original.input_ct_hashes == restored.input_ct_hashes,
          "input_ct_hashes values match");
    check(original.output_ct_hash == restored.output_ct_hash,
          "output_ct_hash round-trips");

    // Verify hex encoding is correct.
    check(to_hex(original.nonce) == "deadbeef01020304",
          "nonce hex encoding correct");
}

int main() {
    std::cout << "=== tee-vfhe common types test ===" << std::endl;

    test_blake3_kat();
    test_ciphertext_roundtrip();
    test_transcript_json();

    std::cout << std::endl;
    if (failures == 0) {
        std::cout << "ALL TESTS PASSED" << std::endl;
        return 0;
    }
    std::cout << failures << " TEST(S) FAILED" << std::endl;
    return 1;
}
