// Correctness tests for all Wave 4 workloads (including noop).
// Each test registers all workloads, looks up by id, builds a deterministic
// context + keys, encrypts known input(s), runs eval, decrypts, and compares
// against the plaintext expected result within the specified tolerance.

#include <gtest/gtest.h>

#include <cmath>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

#include "openfhe.h"
#include "server/workload_registry.h"

using namespace tee;
using namespace lbcrypto;

namespace {

// Reference floor of 1.0 avoids division-by-zero for near-zero expected values.
void check_relative_error(const std::vector<double>& expected,
                          const std::vector<double>& actual,
                          double tol, const std::string& ctx) {
    ASSERT_EQ(expected.size(), actual.size()) << ctx;
    for (size_t i = 0; i < expected.size(); ++i) {
        double ref = std::max(1.0, std::abs(expected[i]));
        EXPECT_LT(std::abs(expected[i] - actual[i]) / ref, tol)
            << ctx << " mismatch at slot " << i
            << " expected=" << expected[i] << " actual=" << actual[i];
    }
}

struct WorkloadSetup {
    const Workload* w;
    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> kp;
};

WorkloadSetup setup_workload(const std::string& id) {
    auto& reg = get_workload_registry();
    auto it = reg.find(id);
    if (it == reg.end()) {
        throw std::runtime_error("workload not found: " + id);
    }
    WorkloadSetup s;
    s.w = &it->second;
    s.cc = s.w->make_context();
    s.kp = s.cc->KeyGen();
    if (s.w->gen_keys) s.w->gen_keys(s.cc, s.kp);
    s.cc->EvalMultKeyGen(s.kp.secretKey);
    return s;
}

std::vector<double> decrypt_to_vector(CryptoContext<DCRTPoly> cc,
                                      const KeyPair<DCRTPoly>& kp,
                                      const Ciphertext<DCRTPoly>& ct,
                                      size_t n) {
    Plaintext pt;
    cc->Decrypt(kp.secretKey, ct, &pt);
    pt->SetLength(n);
    auto dec = pt->GetCKKSPackedValue();
    std::vector<double> result(n);
    for (size_t i = 0; i < n; ++i) result[i] = dec[i].real();
    return result;
}

std::vector<double> make_input(size_t n) {
    std::mt19937 gen(42);
    std::uniform_real_distribution<double> dist(-1.0, 1.0);
    std::vector<double> v(n);
    for (size_t i = 0; i < n; ++i) v[i] = dist(gen);
    return v;
}

Ciphertext<DCRTPoly> encrypt_vector(CryptoContext<DCRTPoly> cc,
                                    PublicKey<DCRTPoly> pk,
                                    const std::vector<double>& v) {
    return cc->Encrypt(pk, cc->MakeCKKSPackedPlaintext(v));
}

}  // namespace

// ── noop ──────────────────────────────────────────────────────────────────
TEST(Workloads, noop) {
    auto s = setup_workload("noop");
    std::vector<double> v = make_input(32);
    auto ct = encrypt_vector(s.cc, s.kp.publicKey, v);
    auto out = s.w->eval(s.cc, {ct});
    auto actual = decrypt_to_vector(s.cc, s.kp, out, 32);
    check_relative_error(v, actual, 1e-4, "noop");
}

// ── toy: Rescale(c1 * c2) ──────────────────────────────────────────────────
TEST(Workloads, toy) {
    auto s = setup_workload("toy");
    std::vector<double> v1 = make_input(32);
    // Use a fresh stream for v2 so it differs from v1.
    std::mt19937 gen2(123);
    std::uniform_real_distribution<double> dist(-1.0, 1.0);
    std::vector<double> v2(32);
    for (size_t i = 0; i < 32; ++i) v2[i] = dist(gen2);
    std::vector<double> expected(32);
    for (size_t i = 0; i < 32; ++i) expected[i] = v1[i] * v2[i];

    auto ct1 = encrypt_vector(s.cc, s.kp.publicKey, v1);
    auto ct2 = encrypt_vector(s.cc, s.kp.publicKey, v2);
    auto out = s.w->eval(s.cc, {ct1, ct2});
    auto actual = decrypt_to_vector(s.cc, s.kp, out, 32);
    check_relative_error(expected, actual, 1e-4, "toy");
}

// ── small: dot product via EvalSum ─────────────────────────────────────────
TEST(Workloads, small) {
    auto s = setup_workload("small");
    std::vector<double> x = make_input(32);
    // Replicate the workload's fixed weights (seed 42, 32 draws).
    std::mt19937 gen(42);
    std::uniform_real_distribution<double> dist(-1.0, 1.0);
    std::vector<double> w(32);
    for (size_t i = 0; i < 32; ++i) w[i] = dist(gen);
    double expected = 0.0;
    for (size_t i = 0; i < 32; ++i) expected += w[i] * x[i];

    auto ct = encrypt_vector(s.cc, s.kp.publicKey, x);
    auto out = s.w->eval(s.cc, {ct});
    auto actual = decrypt_to_vector(s.cc, s.kp, out, 32);
    // Slot 0 holds the dot product; remaining slots may hold partial sums.
    double ref = std::max(1.0, std::abs(expected));
    EXPECT_LT(std::abs(expected - actual[0]) / ref, 1e-3)
        << "small dot product mismatch";
}

// ── medium: 64x64 matvec (diagonal method) ─────────────────────────────────
TEST(Workloads, medium) {
    auto s = setup_workload("medium");
    std::vector<double> x = make_input(64);
    // Replicate the workload's fixed 64x64 matrix (seed 42).
    std::mt19937 gen(42);
    std::uniform_real_distribution<double> dist(-1.0, 1.0);
    std::vector<std::vector<double>> W(64, std::vector<double>(64));
    for (size_t i = 0; i < 64; ++i)
        for (size_t j = 0; j < 64; ++j) W[i][j] = dist(gen);
    std::vector<double> expected(64);
    for (size_t i = 0; i < 64; ++i) {
        double acc = 0.0;
        for (size_t j = 0; j < 64; ++j) acc += W[i][j] * x[j];
        expected[i] = acc;
    }

    auto ct = encrypt_vector(s.cc, s.kp.publicKey, x);
    auto out = s.w->eval(s.cc, {ct});
    auto actual = decrypt_to_vector(s.cc, s.kp, out, 64);
    check_relative_error(expected, actual, 1e-2, "medium");
}

// ── micro_add ───────────────────────────────────────────────────────────────
TEST(Workloads, micro_add) {
    auto s = setup_workload("micro_add");
    std::vector<double> v1 = make_input(32);
    std::mt19937 gen2(123);
    std::uniform_real_distribution<double> dist(-1.0, 1.0);
    std::vector<double> v2(32);
    for (size_t i = 0; i < 32; ++i) v2[i] = dist(gen2);
    std::vector<double> expected(32);
    for (size_t i = 0; i < 32; ++i) expected[i] = v1[i] + v2[i];

    auto ct1 = encrypt_vector(s.cc, s.kp.publicKey, v1);
    auto ct2 = encrypt_vector(s.cc, s.kp.publicKey, v2);
    auto out = s.w->eval(s.cc, {ct1, ct2});
    auto actual = decrypt_to_vector(s.cc, s.kp, out, 32);
    check_relative_error(expected, actual, 1e-4, "micro_add");
}

// ── micro_mul ───────────────────────────────────────────────────────────────
TEST(Workloads, micro_mul) {
    auto s = setup_workload("micro_mul");
    std::vector<double> v1 = make_input(32);
    std::mt19937 gen2(123);
    std::uniform_real_distribution<double> dist(-1.0, 1.0);
    std::vector<double> v2(32);
    for (size_t i = 0; i < 32; ++i) v2[i] = dist(gen2);
    std::vector<double> expected(32);
    for (size_t i = 0; i < 32; ++i) expected[i] = v1[i] * v2[i];

    auto ct1 = encrypt_vector(s.cc, s.kp.publicKey, v1);
    auto ct2 = encrypt_vector(s.cc, s.kp.publicKey, v2);
    auto out = s.w->eval(s.cc, {ct1, ct2});
    auto actual = decrypt_to_vector(s.cc, s.kp, out, 32);
    check_relative_error(expected, actual, 1e-4, "micro_mul");
}

// ── micro_mul_rescale ───────────────────────────────────────────────────────
TEST(Workloads, micro_mul_rescale) {
    auto s = setup_workload("micro_mul_rescale");
    std::vector<double> v1 = make_input(32);
    std::mt19937 gen2(123);
    std::uniform_real_distribution<double> dist(-1.0, 1.0);
    std::vector<double> v2(32);
    for (size_t i = 0; i < 32; ++i) v2[i] = dist(gen2);
    std::vector<double> expected(32);
    for (size_t i = 0; i < 32; ++i) expected[i] = v1[i] * v2[i];

    auto ct1 = encrypt_vector(s.cc, s.kp.publicKey, v1);
    auto ct2 = encrypt_vector(s.cc, s.kp.publicKey, v2);
    auto out = s.w->eval(s.cc, {ct1, ct2});
    auto actual = decrypt_to_vector(s.cc, s.kp, out, 32);
    check_relative_error(expected, actual, 1e-4, "micro_mul_rescale");
}

// ── micro_rotate ────────────────────────────────────────────────────────────
TEST(Workloads, micro_rotate) {
    auto s = setup_workload("micro_rotate");
    std::vector<double> v = make_input(32);
    // EvalRotate(ct, 1) is a left rotation: result[i] = v[(i+1) % 32].
    std::vector<double> expected(32);
    for (size_t i = 0; i < 32; ++i) expected[i] = v[(i + 1) % 32];

    auto ct = encrypt_vector(s.cc, s.kp.publicKey, v);
    auto out = s.w->eval(s.cc, {ct});
    auto actual = decrypt_to_vector(s.cc, s.kp, out, 32);
    check_relative_error(expected, actual, 1e-5, "micro_rotate");
}

// ── app_matvec: 256x256 matvec (diagonal method) ────────────────────────────
TEST(Workloads, app_matvec) {
    auto s = setup_workload("app_matvec");
    std::vector<double> x = make_input(256);
    // Replicate the workload's fixed 256x256 matrix (seed 42).
    std::mt19937 gen(42);
    std::uniform_real_distribution<double> dist(-1.0, 1.0);
    std::vector<std::vector<double>> A(256, std::vector<double>(256));
    for (size_t i = 0; i < 256; ++i)
        for (size_t j = 0; j < 256; ++j) A[i][j] = dist(gen);
    std::vector<double> expected(256);
    for (size_t i = 0; i < 256; ++i) {
        double acc = 0.0;
        for (size_t j = 0; j < 256; ++j) acc += A[i][j] * x[j];
        expected[i] = acc;
    }

    auto ct = encrypt_vector(s.cc, s.kp.publicKey, x);
    auto out = s.w->eval(s.cc, {ct});
    auto actual = decrypt_to_vector(s.cc, s.kp, out, 256);
    check_relative_error(expected, actual, 1e-1, "app_matvec");
}

// ── app_inference: 1-layer MLP 128->64->10 ──────────────────────────────────
TEST(Workloads, app_inference) {
    auto s = setup_workload("app_inference");
    std::vector<double> x = make_input(128);

    // Replicate the workload's fixed weights (seed 42).
    std::mt19937 gen(42);
    std::uniform_real_distribution<double> dist(-1.0, 1.0);
    // W1: 64x128
    std::vector<std::vector<double>> W1(64, std::vector<double>(128));
    for (size_t i = 0; i < 64; ++i)
        for (size_t j = 0; j < 128; ++j) W1[i][j] = dist(gen);
    // b1: 64
    std::vector<double> b1(64);
    for (size_t i = 0; i < 64; ++i) b1[i] = dist(gen);
    // W2: 10x64
    std::vector<std::vector<double>> W2(10, std::vector<double>(64));
    for (size_t i = 0; i < 10; ++i)
        for (size_t j = 0; j < 64; ++j) W2[i][j] = dist(gen);
    // b2: 10
    std::vector<double> b2(10);
    for (size_t i = 0; i < 10; ++i) b2[i] = dist(gen);

    // Plaintext reference: t = W1*x + b1 (first 64 slots), act = 0.5*t*(1+t),
    // out = W2*act + b2 (first 10 slots).
    std::vector<double> t(128, 0.0);
    for (size_t i = 0; i < 64; ++i) {
        double acc = b1[i];
        for (size_t j = 0; j < 128; ++j) acc += W1[i][j] * x[j];
        t[i] = acc;
    }
    std::vector<double> act(128, 0.0);
    for (size_t i = 0; i < 64; ++i) act[i] = 0.5 * t[i] * (1.0 + t[i]);
    std::vector<double> expected(128, 0.0);
    for (size_t i = 0; i < 10; ++i) {
        double acc = b2[i];
        for (size_t j = 0; j < 64; ++j) acc += W2[i][j] * act[j];
        expected[i] = acc;
    }

    auto ct = encrypt_vector(s.cc, s.kp.publicKey, x);
    auto out = s.w->eval(s.cc, {ct});
    auto actual = decrypt_to_vector(s.cc, s.kp, out, 128);
    // Only first 10 slots carry valid output data.
    check_relative_error(
        std::vector<double>(expected.begin(), expected.begin() + 10),
        std::vector<double>(actual.begin(), actual.begin() + 10),
        1e-1, "app_inference");
}
