#include <gtest/gtest.h>

#include "server/workload_registry.h"
#include "common/serialization.h"
#include "common/zk_proof.h"
#include "libff/common/profiling.hpp"
#include "openfhe.h"
#include "proofsystem/proofsystem_libsnark.h"

#include <chrono>
#include <cstdint>
#include <random>
#include <vector>

using namespace zk;
using namespace lbcrypto;

namespace {

constexpr int64_t kModulus = 65537;

// ── helpers ──────────────────────────────────────────────────────────────────

std::vector<int64_t> generate_input(unsigned seed, size_t batch_size) {
    std::mt19937 gen(seed);
    std::uniform_int_distribution<int64_t> dist(0, 65536);
    std::vector<int64_t> v(batch_size);
    for (size_t i = 0; i < batch_size; ++i) v[i] = dist(gen);
    return v;
}

int64_t norm(int64_t v) { return v < 0 ? v + kModulus : v; }

int64_t mod(int64_t v) {
    v %= kModulus;
    return v < 0 ? v + kModulus : v;
}

CT encrypt(CC cc, PublicKey<DCRTPoly> pk, const std::vector<int64_t>& vals) {
    auto pt = cc->MakePackedPlaintext(vals);
    return cc->Encrypt(pk, pt);
}

std::vector<int64_t> decrypt(CC cc, PrivateKey<DCRTPoly> sk, const CT& ct,
                             size_t batch_size) {
    Plaintext pt;
    cc->Decrypt(sk, ct, &pt);
    pt->SetLength(batch_size);
    auto raw = pt->GetPackedValue();
    std::vector<int64_t> out(batch_size);
    for (size_t i = 0; i < batch_size; ++i) out[i] = norm(raw[i]);
    return out;
}

// ── plaintext reference functions ────────────────────────────────────────────

std::vector<int64_t> ref_noop(const std::vector<std::vector<int64_t>>& in) {
    return in[0];
}

std::vector<int64_t> ref_toy(const std::vector<std::vector<int64_t>>& in) {
    size_t bs = in[0].size();
    std::vector<int64_t> r(bs);
    for (size_t i = 0; i < bs; ++i)
        r[i] = mod(in[0][i] * in[1][i]);
    return r;
}

std::vector<int64_t> ref_small(const std::vector<std::vector<int64_t>>& in) {
    // y = (c1*c2) + (c3*c4) element-wise
    size_t bs = in[0].size();
    std::vector<int64_t> r(bs, 0);
    for (size_t i = 0; i < bs; ++i)
        r[i] = mod(mod(in[0][i] * in[1][i]) + mod(in[2][i] * in[3][i]));
    return r;
}

std::vector<int64_t> ref_medium(const std::vector<std::vector<int64_t>>& in) {
    // y = (c1*c2) + (c3*c4) + (c5*c6) element-wise (depth-1 flattened circuit)
    size_t bs = in[0].size();
    std::vector<int64_t> r(bs, 0);
    for (size_t i = 0; i < bs; ++i) {
        int64_t u1 = mod(in[0][i] * in[1][i]);
        int64_t u2 = mod(in[2][i] * in[3][i]);
        int64_t u3 = mod(in[4][i] * in[5][i]);
        r[i] = mod(mod(u1 + u2) + u3);
    }
    return r;
}

std::vector<int64_t> ref_add(const std::vector<std::vector<int64_t>>& in) {
    size_t bs = in[0].size();
    std::vector<int64_t> r(bs);
    for (size_t i = 0; i < bs; ++i)
        r[i] = mod(in[0][i] + in[1][i]);
    return r;
}

std::vector<int64_t> ref_mul(const std::vector<std::vector<int64_t>>& in) {
    size_t bs = in[0].size();
    std::vector<int64_t> r(bs);
    for (size_t i = 0; i < bs; ++i)
        r[i] = mod(in[0][i] * in[1][i]);
    return r;
}

// ── generic test runner ──────────────────────────────────────────────────────

struct WorkloadTestParams {
    std::string id;
    std::vector<int> seeds;
    std::function<std::vector<int64_t>(const std::vector<std::vector<int64_t>>&)> ref_fn;
    // selection mask: which slots to compare (empty = all)
    std::vector<size_t> check_slots;
};

void run_workload_test(const WorkloadTestParams& p) {
    auto& reg = get_workload_registry();
    auto it = reg.find(p.id);
    ASSERT_NE(it, reg.end()) << "workload not registered: " << p.id;

    auto cc = it->second.make_context();
    ASSERT_NE(cc, nullptr);

    auto kp = cc->KeyGen();
    if (it->second.gen_keys) it->second.gen_keys(cc, kp);
    cc->EvalMultKeyGen(kp.secretKey);

    auto batch_size = cc->GetRingDimension() / 2;

    std::vector<std::vector<int64_t>> inputs;
    std::vector<CT> cts;
    for (size_t i = 0; i < p.seeds.size(); ++i) {
        auto inp = generate_input(p.seeds[i], batch_size);
        inputs.push_back(inp);
        cts.push_back(encrypt(cc, kp.publicKey, inp));
    }

    auto ct_out = it->second.eval(cc, cts);
    auto got = decrypt(cc, kp.secretKey, ct_out, batch_size);

    auto expected = p.ref_fn(inputs);

    if (p.check_slots.empty()) {
        for (size_t i = 0; i < batch_size; ++i) {
            EXPECT_EQ(got[i], expected[i])
                << "mismatch at slot " << i << " for workload " << p.id;
        }
    } else {
        for (auto i : p.check_slots) {
            EXPECT_EQ(got[i], expected[i])
                << "mismatch at slot " << i << " for workload " << p.id;
        }
    }
}

// ── test cases ───────────────────────────────────────────────────────────────

TEST(Workloads, Noop) {
    run_workload_test({"noop", {42}, ref_noop, {}});
}

TEST(Workloads, Toy) {
    run_workload_test({"toy", {42, 165}, ref_toy, {}});
}

TEST(Workloads, Small) {
    run_workload_test({"small", {42, 165, 288, 411}, ref_small, {}});
}

TEST(Workloads, Medium) {
    run_workload_test({"medium", {42, 165, 288, 411, 534, 657}, ref_medium, {}});
}

TEST(Workloads, BGVAdd4K) {
    run_workload_test({"BGV-Add-4K", {42, 165}, ref_add, {}});
}

TEST(Workloads, BGVMul4K) {
    run_workload_test({"BGV-Mul-4K", {42, 165}, ref_mul, {}});
}

// ── ZK pipeline tests ─────────────────────────────────────────────────────────
//
// These tests invoke the real eval_zk / LibsnarkProofSystem pipeline that the
// server uses. They exist because the previous test suite only exercised plain
// FHE eval, allowing the ZK pipeline to be silently broken (wrong key-switch
// technique, wrong firstModSize, buggy Relinearize) without any test failing.
//
// The tests cover:
//   1. Constraint generation completes without crashing (catches HYBRID
//      keyswitch segfault, firstModSize=60 assertion failure).
//   2. Witness generation satisfies the constraint system (catches
//      Relinearize constraint/witness mismatch, missing PublicInput).
//   3. Full Groth16 setup + prove + verify on toy (catches serialization
//      bugs like the BINARY_OUTPUT mismatch).

class ZKEvalTest : public ::testing::Test {
protected:
    void SetUp() override {
        pp::init_public_params();
        // Suppress libff profiling prints (they corrupt test output).
        libff::inhibit_profiling_info = true;
    }

    // Build the SAME context the server uses (baseline params).
    CC make_cc() {
        auto& reg = get_workload_registry();
        return reg.at("toy").make_context();
    }

    // Encrypt N inputs with the given seeds.
    std::pair<std::vector<CT>, KeyPair<DCRTPoly>>
    make_inputs(CC cc, const std::vector<int>& seeds) {
        auto kp = cc->KeyGen();
        cc->EvalMultKeyGen(kp.secretKey);
        size_t batch = cc->GetRingDimension() / 2;
        std::vector<CT> cts;
        for (int s : seeds) {
            auto vals = generate_input(s, batch);
            cts.push_back(encrypt(cc, kp.publicKey, vals));
        }
        return {cts, kp};
    }

    // Serialize + deserialize to match the server's flow (fresh ct objects
    // for each ZK pass, since PublicInput attaches metadata).
    std::vector<CT> fresh_inputs(const std::vector<CT>& cts) {
        std::vector<CT> out;
        for (auto& ct : cts) {
            std::string s = serialize_ciphertext(ct);
            out.push_back(deserialize_ciphertext(s));
        }
        return out;
    }
};

// Test 1: All ZK-enabled workloads produce a satisfied constraint system.
// This catches: wrong keyswitch (segfault), wrong firstModSize (assertion),
// Relinearize bugs (unsatisfied), missing PublicInput (errors).
TEST_F(ZKEvalTest, AllWorkloadsProduceSatisfiedConstraintSystem) {
    struct Case { std::string id; std::vector<int> seeds; };
    std::vector<Case> cases = {
        {"toy",        {42, 165}},
        {"small",      {42, 165, 288, 411}},
        {"medium",     {42, 165, 288, 411, 534, 657}},
        {"BGV-Mul-4K", {42, 165}},
    };

    for (const auto& c : cases) {
        SCOPED_TRACE("workload=" + c.id);
        auto& reg = get_workload_registry();
        auto it = reg.find(c.id);
        ASSERT_NE(it, reg.end()) << "workload not registered";
        ASSERT_TRUE(it->second.eval_zk) << "workload has no eval_zk";

        auto cc = it->second.make_context();
        auto [cts, kp] = make_inputs(cc, c.seeds);

        // Pass 1: constraint generation
        LibsnarkProofSystem ps(cc);
        auto zk_inputs_1 = fresh_inputs(cts);
        ps.SetMode(PROOFSYSTEM_MODE_CONSTRAINT_GENERATION);
        auto out1 = it->second.eval_zk(ps, zk_inputs_1);
        (void)out1;
        auto cs = ps.pb.get_constraint_system();

        // Pass 2: witness generation
        auto zk_inputs_2 = fresh_inputs(cts);
        ps.SetMode(PROOFSYSTEM_MODE_WITNESS_GENERATION);
        auto out2 = it->second.eval_zk(ps, zk_inputs_2);
        (void)out2;

        auto primary = ps.pb.primary_input();
        auto aux = ps.pb.auxiliary_input();

        EXPECT_GT(cs.num_constraints(), 0u)
            << "ZK workload " << c.id << " produced 0 constraints";
        EXPECT_TRUE(cs.is_satisfied(primary, aux))
            << "ZK workload " << c.id << " constraint system not satisfied";
    }
}

// Test 2: BGV-Add-4K produces an empty constraint system (EvalAdd is linear,
// no R1CS constraints). This documents the expected behavior.
TEST_F(ZKEvalTest, BGVAdd4KHasEmptyConstraintSystem) {
    auto& reg = get_workload_registry();
    auto it = reg.find("BGV-Add-4K");
    ASSERT_NE(it, reg.end());
    ASSERT_TRUE(it->second.eval_zk);

    auto cc = it->second.make_context();
    auto [cts, kp] = make_inputs(cc, {42, 165});

    LibsnarkProofSystem ps(cc);
    auto zk_inputs = fresh_inputs(cts);
    ps.SetMode(PROOFSYSTEM_MODE_CONSTRAINT_GENERATION);
    auto out = it->second.eval_zk(ps, zk_inputs);
    (void)out;
    auto cs = ps.pb.get_constraint_system();
    EXPECT_EQ(cs.num_constraints(), 0u)
        << "EvalAdd-only workload should produce 0 R1CS constraints";
}

// Test 3: Full Groth16 pipeline on toy (setup + prove + verify).
// This catches serialization bugs (BINARY_OUTPUT mismatch) and verifies
// the proof actually validates. Takes ~30s at ring=8192.
TEST_F(ZKEvalTest, ToyFullGroth16Pipeline) {
    auto& reg = get_workload_registry();
    auto it = reg.find("toy");
    ASSERT_NE(it, reg.end());

    auto cc = it->second.make_context();
    auto [cts, kp] = make_inputs(cc, {42, 165});

    // Pass 1 + 2: constraint + witness generation
    LibsnarkProofSystem ps(cc);
    {
        auto zk_in = fresh_inputs(cts);
        ps.SetMode(PROOFSYSTEM_MODE_CONSTRAINT_GENERATION);
        auto out = it->second.eval_zk(ps, zk_in);
        (void)out;
    }
    {
        auto zk_in = fresh_inputs(cts);
        ps.SetMode(PROOFSYSTEM_MODE_WITNESS_GENERATION);
        auto out = it->second.eval_zk(ps, zk_in);
        (void)out;
    }
    auto cs = ps.pb.get_constraint_system();
    auto primary = ps.pb.primary_input();
    auto aux = ps.pb.auxiliary_input();
    ASSERT_TRUE(cs.is_satisfied(primary, aux)) << "constraint system not satisfied";

    // Pass 3: setup + prove
    auto vk = zk::setup(cs);
    auto proof = zk::prove(primary, aux);

    // Verify the proof
    bool ok = zk::verify_proof(vk, primary, proof);
    EXPECT_TRUE(ok) << "Groth16 proof verification failed";

    // Tamper test: flip a bit in the serialized proof -> should fail
    auto proof_bytes = zk::serialize_proof(proof);
    ASSERT_GT(proof_bytes.size(), 0u);
    proof_bytes[0] ^= 0xFF;
    auto tampered = zk::deserialize_proof(proof_bytes);
    EXPECT_FALSE(zk::verify_proof(vk, primary, tampered))
        << "tampered proof should NOT verify";

    // Serialization round-trip test (catches BINARY_OUTPUT mismatch)
    auto pi_bytes = zk::serialize_public_inputs(primary);
    auto pi_back = zk::deserialize_public_inputs(pi_bytes);
    EXPECT_EQ(pi_back.size(), primary.size());
    for (size_t i = 0; i < primary.size() && i < pi_back.size(); ++i) {
        EXPECT_EQ(primary[i], pi_back[i])
            << "public input " << i << " differs after round-trip";
    }

    zk::clear_cached_keypair();
}

}  // namespace
