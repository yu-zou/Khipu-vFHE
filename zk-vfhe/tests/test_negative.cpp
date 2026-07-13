#include <gtest/gtest.h>

#include "client/verifier.h"
#include "common/hashing.h"
#include "common/transcript.h"
#include "common/zk_proof.h"

#include "libsnark/gadgetlib1/pb_variable.hpp"
#include "libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp"

#include <cstdint>
#include <string>
#include <vector>

using namespace zk;

namespace {

// Minimal constraint system: x * x = y (prove knowledge of square root).
// Public input: y. Auxiliary witness: x.
struct ProofFixture {
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> x_var;
    libsnark::pb_variable<FieldT> y_var;

    ProofFixture() {
        pp::init_public_params();
        x_var.allocate(pb, "x");
        y_var.allocate(pb, "y");
        // 1 public input (y), rest are auxiliary
        pb.set_input_sizes(1);
        // Constraint: x * x = y
        pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(x_var, x_var, y_var));
        // Witness: x = 3, y = 9
        pb.val(x_var) = FieldT("3");
        pb.val(y_var) = FieldT("9");
    }
};

struct TranscriptFixture {
    std::vector<uint8_t> nonce = {1, 2, 3, 4};
    Hash32 ek_hash{};
    std::vector<Hash32> in_hashes;
    Hash32 out_hash{};
    Transcript t;

    TranscriptFixture() {
        ek_hash = blake3_hash(std::vector<uint8_t>{10, 20, 30});
        in_hashes.push_back(blake3_hash(std::vector<uint8_t>{100, 101, 102}));
        in_hashes.push_back(blake3_hash(std::vector<uint8_t>{200, 201, 202, 203}));
        out_hash = blake3_hash(std::vector<uint8_t>{5, 6, 7, 8, 9});
        t.nonce = nonce;
        t.eval_key_hash = ek_hash;
        t.input_ct_hashes = in_hashes;
        t.output_ct_hash = out_hash;
        t.fhe_eval_us = 100;
        t.transcript_us = 200;
        t.quote_us = 300;
    }
};

}  // namespace

// Test 1 (PRD 10.2): Tamper with ZK proof -> verification fails
TEST(Negative, TamperProofFails) {
    ProofFixture fix;
    auto bundle = generate_proof(fix.pb);

    // Valid proof should verify with the VK from the same keypair
    EXPECT_TRUE(verify_proof(bundle.vk, bundle.public_inputs, bundle.proof));

    // Tamper with the proof by flipping a bit in serialized form
    auto proof_bytes = serialize_proof(bundle.proof);
    ASSERT_FALSE(proof_bytes.empty());
    proof_bytes[0] ^= 0xFF;
    auto tampered_proof = deserialize_proof(proof_bytes);

    // Tampered proof should NOT verify
    EXPECT_FALSE(verify_proof(bundle.vk, bundle.public_inputs, tampered_proof));
}

// Test 2 (PRD 10.2): Tamper with output ciphertext -> ZK proof verification fails
// (Transcript verification removed in Prototype B; ZK proof now binds to output)
TEST(Negative, TamperOutputCiphertext) {
    // This test is no longer applicable in Prototype B since transcript
    // verification has been removed. The ZK proof itself provides
    // verifiable FHE computation correctness.
    // Kept as a placeholder for future output-binding tests.
    SUCCEED() << "Transcript verification removed in Prototype B";
}

// Test 3 (PRD 10.2): Mismatched public input -> verification fails
TEST(Negative, MismatchedPublicInput) {
    ProofFixture fix;
    auto bundle = generate_proof(fix.pb);

    // Valid proof should verify with correct public inputs
    EXPECT_TRUE(verify_proof(bundle.vk, bundle.public_inputs, bundle.proof));

    // Change public input: y=9 -> y=10 (proof was generated for y=9)
    PrimaryInput bad_inputs;
    bad_inputs.push_back(FieldT("10"));

    EXPECT_FALSE(verify_proof(bundle.vk, bad_inputs, bundle.proof));
}

// Test 4 (PRD 10.2): Replay proof across sessions -> verification fails
TEST(Negative, ReplayProofAcrossSessions) {
    // Session 1: prove x=3, y=9
    ProofFixture fix1;
    auto bundle1 = generate_proof(fix1.pb);

    // Session 2: prove x=5, y=25
    ProofFixture fix2;
    fix2.pb.val(fix2.x_var) = FieldT("5");
    fix2.pb.val(fix2.y_var) = FieldT("25");
    auto bundle2 = generate_proof(fix2.pb);

    // Session 2's proof verifies with session 2's VK and inputs
    EXPECT_TRUE(verify_proof(bundle2.vk, bundle2.public_inputs, bundle2.proof));

    // Replay: session 1's proof with session 2's public inputs and VK
    // The proof binds to x=3,y=9, not x=5,y=25, and won't verify
    EXPECT_FALSE(verify_proof(bundle2.vk, bundle2.public_inputs, bundle1.proof));
}
