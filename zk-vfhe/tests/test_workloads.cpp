#include <gtest/gtest.h>

#include "server/workload_registry.h"
#include "openfhe.h"

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
    // u1=c1*c2, u2=c3*c4, u3=c5*c6, y=(u1+u2)*u3
    size_t bs = in[0].size();
    std::vector<int64_t> r(bs, 0);
    for (size_t i = 0; i < bs; ++i) {
        int64_t u1 = mod(in[0][i] * in[1][i]);
        int64_t u2 = mod(in[2][i] * in[3][i]);
        int64_t u3 = mod(in[4][i] * in[5][i]);
        r[i] = mod(mod(u1 + u2) * u3);
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

}  // namespace
