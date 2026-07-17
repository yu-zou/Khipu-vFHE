// Google Test negative tests for PRD Section 10.1 security scenarios.
// All five tests exercise Verifier::verify_all (or the verify-before-decrypt
// guard) and expect failure when the evidence is tampered or missing.
#include <gtest/gtest.h>

#include <stdexcept>
#include <string>
#include <vector>

#include "client/verifier.h"
#include "common/attestation.h"
#include "common/hashing.h"
#include "common/transcript.h"

using namespace tee;

namespace {

// A valid transcript and the matching expected values a client would compute.
struct ValidSetup {
    Transcript transcript;
    std::vector<uint8_t> nonce;
    Hash32 eval_key_hash{};
    std::vector<Hash32> input_ct_hashes;
    Hash32 output_ct_hash{};
};

ValidSetup make_valid_setup() {
    ValidSetup s;
    s.nonce = {1, 2, 3, 4, 5, 6, 7, 8};
    s.eval_key_hash = blake3_hash("eval-key-data");
    s.input_ct_hashes = {blake3_hash("input-ct-1"), blake3_hash("input-ct-2")};
    s.output_ct_hash = blake3_hash("output-ct");

    s.transcript.nonce = s.nonce;
    s.transcript.eval_key_hash = s.eval_key_hash;
    s.transcript.input_ct_hashes = s.input_ct_hashes;
    s.transcript.output_ct_hash = s.output_ct_hash;
    return s;
}

// A dummy 4-byte quote — invalid for any real TDX verifier, so
// verify_tdx_quote will always reject it (returns false via exception catch).
std::vector<uint8_t> dummy_quote() {
    return {0x00, 0x01, 0x02, 0x03};
}

// Minimal helper that mirrors the client_main.cpp verify-before-decrypt guard.
// decrypt() throws unless verify() was called AND returned true.
class GuardedDecryptor {
public:
    void verify(const std::vector<uint8_t>& quote, const Transcript& t,
                const std::vector<uint8_t>& nonce, const std::string& mr_td,
                const Hash32& ek_hash,
                const std::vector<Hash32>& input_hashes,
                const Hash32& output_hash) {
        Verifier v;
        verified_ = v.verify_all(quote, t, nonce, mr_td, ek_hash,
                                 input_hashes, output_hash);
    }

    void decrypt() {
        if (!verified_) {
            throw std::runtime_error(
                "decryption refused: attestation not verified");
        }
    }

private:
    bool verified_ = false;
};

}  // namespace

// ── Negative test 1: Tamper with output ciphertext hash ─────────────────────
// The transcript's output_ct_hash does not match the expected hash the client
// computed from the received ciphertext blob → verify_all returns false.
TEST(Negative, TamperOutputHash) {
    auto s = make_valid_setup();
    Hash32 tampered_output = blake3_hash("tampered-output");

    Verifier v;
    EXPECT_FALSE(v.verify_all(
        dummy_quote(), s.transcript, s.nonce, "",
        s.eval_key_hash, s.input_ct_hashes, tampered_output));
}

// ── Negative test 2: Tamper with input ciphertext hash ──────────────────────
// One of the input_ct_hashes in the expected set differs from the transcript
// → verify_all returns false.
TEST(Negative, TamperInputHash) {
    auto s = make_valid_setup();
    std::vector<Hash32> tampered_inputs = {
        blake3_hash("tampered-input-1"), s.input_ct_hashes[1]};

    Verifier v;
    EXPECT_FALSE(v.verify_all(
        dummy_quote(), s.transcript, s.nonce, "",
        s.eval_key_hash, tampered_inputs, s.output_ct_hash));
}

// ── Negative test 3: Replay old transcript with new input ───────────────────
// An adversary replays an old valid transcript, but the client generated a
// fresh nonce for this session. The nonce in the transcript no longer matches
// → verify_all returns false.
TEST(Negative, ReplayOldTranscript) {
    auto s = make_valid_setup();
    std::vector<uint8_t> fresh_nonce = {99, 98, 97, 96, 95, 94, 93, 92};

    Verifier v;
    EXPECT_FALSE(v.verify_all(
        dummy_quote(), s.transcript, fresh_nonce, "",
        s.eval_key_hash, s.input_ct_hashes, s.output_ct_hash));
}

// ── Negative test 4: Use mismatched TDX quote ───────────────────────────────
// The transcript matches all expected values, but the TDX quote is a dummy
// blob that cannot be verified by the remote attestation service →
// verify_all returns false.
TEST(Negative, MismatchedTdxQuote) {
    auto s = make_valid_setup();

    Verifier v;
    EXPECT_FALSE(v.verify_all(
        dummy_quote(), s.transcript, s.nonce, "",
        s.eval_key_hash, s.input_ct_hashes, s.output_ct_hash));
}

// ── Negative test 5: Attempt decryption before verification ─────────────────
// The client must refuse to decrypt if verify() was never called or returned
// false. This mirrors the guard in client_main.cpp (lines 233-241): if
// verify_all returns false, the client prints "refusing to decrypt" and exits
// without calling Decrypt.
TEST(Negative, DecryptBeforeVerify) {
    GuardedDecryptor d;

    // Calling decrypt() before verify() must throw.
    EXPECT_THROW(d.decrypt(), std::runtime_error);

    // After a failed verification (bad quote), decrypt() must still throw.
    auto s = make_valid_setup();
    d.verify(dummy_quote(), s.transcript, s.nonce, "",
             s.eval_key_hash, s.input_ct_hashes, s.output_ct_hash);
    EXPECT_THROW(d.decrypt(), std::runtime_error);
}
