// Workload "app_inference": one-hidden-layer MLP.
//   x(128) -> W1*x + b1 (64) -> f(t)=0.5*t*(1+t) -> W2*act + b2 (10)
// Inputs: 1 ciphertext (length-128 float64 vector x). Output: length-128
// ciphertext with valid data in first 10 slots.
// depth=5, scaling=50, batch=128, FIXEDMANUAL, HEStd_128_classic. tol < 1e-1.
// gen_keys: EvalRotateKeyGen indices {0..127}.

#include "server/workload_registry.h"

#include <random>
#include <stdexcept>
#include <vector>

#include "openfhe.h"
#include "openfhe/pke/cryptocontext-ser.h"
#include "openfhe/pke/key/key-ser.h"
#include "openfhe/pke/scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;

namespace tee {
namespace {

constexpr size_t kInDim   = 128;
constexpr size_t kHidden  = 64;
constexpr size_t kOutDim  = 10;
constexpr size_t kSlots   = 128;  // == kInDim, diagonal method uses N=128

// Fixed deterministic weights (seed 42, uniform [-1, 1]).
struct MlpWeights {
    std::vector<std::vector<double>> W1;  // [kHidden][kInDim]
    std::vector<double> b1;               // [kHidden]
    std::vector<std::vector<double>> W2;  // [kOutDim][kHidden]
    std::vector<double> b2;               // [kOutDim]
};

MlpWeights make_mlp_weights() {
    std::mt19937 gen(42);
    std::uniform_real_distribution<double> dist(-1.0, 1.0);
    MlpWeights w;
    w.W1.assign(kHidden, std::vector<double>(kInDim));
    for (size_t i = 0; i < kHidden; ++i)
        for (size_t j = 0; j < kInDim; ++j) w.W1[i][j] = dist(gen);
    w.b1.assign(kHidden, 0.0);
    for (size_t i = 0; i < kHidden; ++i) w.b1[i] = dist(gen);
    w.W2.assign(kOutDim, std::vector<double>(kHidden));
    for (size_t i = 0; i < kOutDim; ++i)
        for (size_t j = 0; j < kHidden; ++j) w.W2[i][j] = dist(gen);
    w.b2.assign(kOutDim, 0.0);
    for (size_t i = 0; i < kOutDim; ++i) w.b2[i] = dist(gen);
    return w;
}

CryptoContext<DCRTPoly> make_app_inference_context() {
    CCParams<CryptoContextCKKSRNS> params;
    params.SetMultiplicativeDepth(5);
    params.SetScalingModSize(50);
    params.SetBatchSize(kSlots);
    params.SetScalingTechnique(FIXEDMANUAL);
    params.SetSecurityLevel(HEStd_128_classic);
    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    return cc;
}

// Diagonal matvec: out = M * x where M is rows x cols embedded into a
// kSlots x kSlots matrix (M_full[i][j] = M[i][j] for i<rows, j<cols else 0).
// Result is a length-kSlots ciphertext with valid data in first `rows` slots.
// `acc` inputs must all be at the same depth; one Rescale at the end.
Ciphertext<DCRTPoly> diagonal_matvec(CryptoContext<DCRTPoly> cc,
                                     const Ciphertext<DCRTPoly>& x,
                                     const std::vector<std::vector<double>>& M,
                                     size_t rows, size_t cols) {
    Ciphertext<DCRTPoly> acc;
    for (size_t d = 0; d < kSlots; ++d) {
        std::vector<double> diag(kSlots, 0.0);
        for (size_t i = 0; i < rows; ++i) {
            size_t j = (i + d) % kSlots;
            if (j < cols) diag[i] = M[i][j];
        }
        auto ptxt_diag = cc->MakeCKKSPackedPlaintext(diag);
        auto ct_rot = cc->EvalRotate(x, static_cast<int32_t>(d));
        auto ct_term = cc->EvalMult(ct_rot, ptxt_diag);
        if (d == 0) {
            acc = ct_term;
        } else {
            acc = cc->EvalAdd(acc, ct_term);
        }
    }
    return cc->Rescale(acc);
}

Ciphertext<DCRTPoly> app_inference_eval(
    CryptoContext<DCRTPoly> cc,
    const std::vector<Ciphertext<DCRTPoly>>& inputs) {
    if (inputs.size() != 1) {
        throw std::runtime_error("app_inference workload requires exactly 1 input ciphertext");
    }
    auto w = make_mlp_weights();
    const auto& x = inputs[0];

    // Layer 1: t = W1 * x + b1. W1 is 64x128; result valid in first 64 slots.
    auto t = diagonal_matvec(cc, x, w.W1, kHidden, kInDim);

    // Add bias b1 in first 64 slots.
    std::vector<double> b1_vec(kSlots, 0.0);
    for (size_t i = 0; i < kHidden; ++i) b1_vec[i] = w.b1[i];
    auto pt_b1 = cc->MakeCKKSPackedPlaintext(b1_vec);
    t = cc->EvalAdd(t, pt_b1);

    // Activation f(t) = 0.5 * t * (1 + t), factored to keep levels aligned.
    std::vector<double> ones(kSlots, 1.0);
    std::vector<double> halfs(kSlots, 0.5);
    auto pt_one  = cc->MakeCKKSPackedPlaintext(ones);
    auto pt_half = cc->MakeCKKSPackedPlaintext(halfs);

    auto one_plus_t = cc->EvalAdd(t, pt_one);
    auto t_times_1pt = cc->Rescale(cc->EvalMult(t, one_plus_t));
    // act = 0.5 * t * (1 + t)
    auto act = cc->Rescale(cc->EvalMult(t_times_1pt, pt_half));

    // Layer 2: out = W2 * act + b2. W2 is 10x64; result valid in first 10 slots.
    auto out = diagonal_matvec(cc, act, w.W2, kOutDim, kHidden);

    std::vector<double> b2_vec(kSlots, 0.0);
    for (size_t i = 0; i < kOutDim; ++i) b2_vec[i] = w.b2[i];
    auto pt_b2 = cc->MakeCKKSPackedPlaintext(b2_vec);
    out = cc->EvalAdd(out, pt_b2);

    return out;
}

void app_inference_gen_keys(CryptoContext<DCRTPoly> cc, const KeyPair<DCRTPoly>& kp) {
    std::vector<int32_t> indices(kSlots);
    for (size_t i = 0; i < kSlots; ++i) indices[i] = static_cast<int32_t>(i);
    cc->EvalRotateKeyGen(kp.secretKey, indices);
}

}  // namespace

// Self-register the app_inference workload
static Register g_app_inference_reg("app_inference", Workload{make_app_inference_context, app_inference_eval, app_inference_gen_keys});

}  // namespace tee
