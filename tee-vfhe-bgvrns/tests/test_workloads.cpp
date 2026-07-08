#include <gtest/gtest.h>

#include "server/workload_registry.h"
#include "openfhe.h"

#include <cstdint>
#include <random>
#include <vector>

using namespace tee;
using namespace lbcrypto;

namespace {

constexpr int64_t kModulus = 65537;
constexpr size_t kBatchSize = 64;

// ── helpers ──────────────────────────────────────────────────────────────────

std::vector<int64_t> generate_input(unsigned seed) {
    std::mt19937 gen(seed);
    std::uniform_int_distribution<int64_t> dist(0, 65536);
    std::vector<int64_t> v(kBatchSize);
    for (size_t i = 0; i < kBatchSize; ++i) v[i] = dist(gen);
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

std::vector<int64_t> decrypt(CC cc, PrivateKey<DCRTPoly> sk, const CT& ct) {
    Plaintext pt;
    cc->Decrypt(sk, ct, &pt);
    pt->SetLength(kBatchSize);
    auto raw = pt->GetPackedValue();
    std::vector<int64_t> out(kBatchSize);
    for (size_t i = 0; i < kBatchSize; ++i) out[i] = norm(raw[i]);
    return out;
}

// ── plaintext reference functions ────────────────────────────────────────────

std::vector<int64_t> ref_noop(const std::vector<int64_t>& a) { return a; }

std::vector<int64_t> ref_toy(const std::vector<int64_t>& a,
                              const std::vector<int64_t>& b) {
    std::vector<int64_t> r(kBatchSize);
    for (size_t i = 0; i < kBatchSize; ++i)
        r[i] = mod(a[i] * b[i]);
    return r;
}

std::vector<int64_t> ref_small(const std::vector<int64_t>& a) {
    // dot product sum_{i=0..31} (i+1)*a[i] mod 65537
    int64_t sum = 0;
    for (size_t i = 0; i < 32; ++i)
        sum = mod(sum + mod((static_cast<int64_t>(i) + 1) * a[i]));
    std::vector<int64_t> r(kBatchSize, 0);
    r[0] = sum;
    return r;
}

std::vector<int64_t> ref_medium(const std::vector<int64_t>& a) {
    std::vector<int64_t> r(kBatchSize, 0);
    for (int i = 0; i < 64; ++i) {
        int64_t sum = 0;
        for (int j = 0; j < 64; ++j) {
            int64_t w = static_cast<int64_t>(
                (static_cast<uint64_t>(i) * 64 + static_cast<uint64_t>(j) + 1) %
                static_cast<uint64_t>(kModulus));
            sum = mod(sum + mod(w * a[j]));
        }
        r[i] = sum;
    }
    return r;
}

std::vector<int64_t> ref_add(const std::vector<int64_t>& a,
                              const std::vector<int64_t>& b) {
    std::vector<int64_t> r(kBatchSize);
    for (size_t i = 0; i < kBatchSize; ++i)
        r[i] = mod(a[i] + b[i]);
    return r;
}

std::vector<int64_t> ref_mul(const std::vector<int64_t>& a,
                              const std::vector<int64_t>& b) {
    std::vector<int64_t> r(kBatchSize);
    for (size_t i = 0; i < kBatchSize; ++i)
        r[i] = mod(a[i] * b[i]);
    return r;
}

std::vector<int64_t> ref_modswitch(const std::vector<int64_t>& a) { return a; }

std::vector<int64_t> ref_rotate(const std::vector<int64_t>& a) {
    std::vector<int64_t> r(kBatchSize, 0);
    // EvalRotate(ct, 1): left rotation by 1, wraps at ringDim (8192)
    // slot i gets a[i+1] for i=0..62, slot 63 gets 0 (from outside batch)
    for (size_t i = 0; i < 63; ++i) r[i] = a[i + 1];
    r[63] = 0;
    return r;
}

std::vector<int64_t> ref_app_matvec(const std::vector<int64_t>& a) {
    // A from seed 42, 64x64
    std::mt19937 gen(42);
    std::uniform_int_distribution<int64_t> dist(0, kModulus - 1);
    std::vector<std::vector<int64_t>> A(64, std::vector<int64_t>(64));
    for (int i = 0; i < 64; ++i)
        for (int j = 0; j < 64; ++j) A[i][j] = dist(gen);
    std::vector<int64_t> r(kBatchSize, 0);
    for (int i = 0; i < 64; ++i) {
        int64_t sum = 0;
        for (int j = 0; j < 64; ++j)
            sum = mod(sum + mod(A[i][j] * a[j]));
        r[i] = sum;
    }
    return r;
}

std::vector<int64_t> ref_app_inference(const std::vector<int64_t>& a) {
    // W1: 16x32 seed 100, b1: 16 seed 200
    std::mt19937 g1(100);
    std::uniform_int_distribution<int64_t> d1(0, kModulus - 1);
    std::vector<std::vector<int64_t>> W1(16, std::vector<int64_t>(32));
    for (int i = 0; i < 16; ++i)
        for (int j = 0; j < 32; ++j) W1[i][j] = d1(g1);
    std::mt19937 g2(200);
    std::uniform_int_distribution<int64_t> d2(0, kModulus - 1);
    std::vector<int64_t> b1(16);
    for (int i = 0; i < 16; ++i) b1[i] = d2(g2);
    // z1 = W1 * a + b1  (16 values)
    std::vector<int64_t> z1(16, 0);
    for (int i = 0; i < 16; ++i) {
        int64_t sum = 0;
        for (int j = 0; j < 32; ++j)
            sum = mod(sum + mod(W1[i][j] * a[j]));
        z1[i] = mod(sum + b1[i]);
    }
    // z2 = z1^2 (16 values)
    std::vector<int64_t> z2(16);
    for (int i = 0; i < 16; ++i) z2[i] = mod(z1[i] * z1[i]);
    // W2: 10x16 seed 300, b2: 10 seed 400
    std::mt19937 g3(300);
    std::uniform_int_distribution<int64_t> d3(0, kModulus - 1);
    std::vector<std::vector<int64_t>> W2(10, std::vector<int64_t>(16));
    for (int i = 0; i < 10; ++i)
        for (int j = 0; j < 16; ++j) W2[i][j] = d3(g3);
    std::mt19937 g4(400);
    std::uniform_int_distribution<int64_t> d4(0, kModulus - 1);
    std::vector<int64_t> b2(10);
    for (int i = 0; i < 10; ++i) b2[i] = d4(g4);
    // y = W2 * z2 + b2  (10 values)
    std::vector<int64_t> r(kBatchSize, 0);
    for (int i = 0; i < 10; ++i) {
        int64_t sum = 0;
        for (int j = 0; j < 16; ++j)
            sum = mod(sum + mod(W2[i][j] * z2[j]));
        r[i] = mod(sum + b2[i]);
    }
    return r;
}

// ── generic test runner ──────────────────────────────────────────────────────

struct WorkloadTestParams {
    std::string id;
    int num_inputs;
    std::function<std::vector<int64_t>(const std::vector<int64_t>&,
                                       const std::vector<int64_t>&)>
        ref_fn;
    // selection mask: which slots to compare (empty = all 64)
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

    auto input_a = generate_input(42);
    auto input_b = generate_input(123);

    std::vector<CT> cts;
    cts.push_back(encrypt(cc, kp.publicKey, input_a));
    if (p.num_inputs >= 2)
        cts.push_back(encrypt(cc, kp.publicKey, input_b));

    auto ct_out = it->second.eval(cc, cts);
    auto got = decrypt(cc, kp.secretKey, ct_out);

    auto expected = p.ref_fn(input_a, input_b);

    if (p.check_slots.empty()) {
        for (size_t i = 0; i < kBatchSize; ++i) {
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
    run_workload_test({"noop", 1,
                       [](const auto& a, const auto&) { return ref_noop(a); },
                       {}});
}

TEST(Workloads, Toy) {
    run_workload_test({"toy", 2,
                       [](const auto& a, const auto& b) { return ref_toy(a, b); },
                       {}});
}

TEST(Workloads, Small) {
    WorkloadTestParams p{"small", 1,
                         [](const auto& a, const auto&) { return ref_small(a); },
                         {0}};
    run_workload_test(p);
}

TEST(Workloads, Medium) {
    run_workload_test({"medium", 1,
                       [](const auto& a, const auto&) { return ref_medium(a); },
                       {}});
}

TEST(Workloads, MicroAdd) {
    run_workload_test({"micro_add", 2,
                       [](const auto& a, const auto& b) { return ref_add(a, b); },
                       {}});
}

TEST(Workloads, MicroMul) {
    run_workload_test({"micro_mul", 2,
                       [](const auto& a, const auto& b) { return ref_mul(a, b); },
                       {}});
}

TEST(Workloads, MicroModswitch) {
    run_workload_test({"micro_modswitch", 1,
                       [](const auto& a, const auto&) { return ref_modswitch(a); },
                       {}});
}

TEST(Workloads, MicroRotate) {
    run_workload_test({"micro_rotate", 1,
                       [](const auto& a, const auto&) { return ref_rotate(a); },
                       {}});
}

TEST(Workloads, AppMatvec) {
    run_workload_test({"app_matvec", 1,
                       [](const auto& a, const auto&) { return ref_app_matvec(a); },
                       {}});
}

TEST(Workloads, AppInference) {
    std::vector<size_t> slots;
    for (size_t i = 0; i < 10; ++i) slots.push_back(i);
    WorkloadTestParams p{"app_inference", 1,
                         [](const auto& a, const auto&) {
                             return ref_app_inference(a);
                         },
                         slots};
    run_workload_test(p);
}

}  // namespace