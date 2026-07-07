// Workload "medium": y = W * x, W is 64x64 dense float32 matrix.
// Inputs: 1 ciphertext (length-64 vector x). Output: length-64 vector ciphertext.
// depth=3, scaling=40, batch=64, FIXEDMANUAL, HEStd_128_classic. tol < 1e-2.
// gen_keys: EvalRotateKeyGen indices {0..63}. Diagonal method, final Rescale.

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

constexpr size_t kN = 64;

// Fixed deterministic 64x64 matrix W (seed 42, uniform [-1, 1]).
std::vector<std::vector<double>> make_medium_matrix() {
    std::mt19937 gen(42);
    std::uniform_real_distribution<double> dist(-1.0, 1.0);
    std::vector<std::vector<double>> W(kN, std::vector<double>(kN));
    for (size_t i = 0; i < kN; ++i)
        for (size_t j = 0; j < kN; ++j) W[i][j] = dist(gen);
    return W;
}

CryptoContext<DCRTPoly> make_medium_context() {
    CCParams<CryptoContextCKKSRNS> params;
    params.SetMultiplicativeDepth(3);
    params.SetScalingModSize(40);
    params.SetBatchSize(kN);
    params.SetScalingTechnique(FIXEDMANUAL);
    params.SetSecurityLevel(HEStd_128_classic);
    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    return cc;
}

Ciphertext<DCRTPoly> medium_eval(CryptoContext<DCRTPoly> cc,
                                 const std::vector<Ciphertext<DCRTPoly>>& inputs) {
    if (inputs.size() != 1) {
        throw std::runtime_error("medium workload requires exactly 1 input ciphertext");
    }
    auto W = make_medium_matrix();
    const auto& x = inputs[0];

    // Diagonal method: result = sum_{d=0}^{N-1} diag_d \odot rot(x, d)
    // where diag_d[i] = W[i][(i+d) % N].
    Ciphertext<DCRTPoly> acc;
    for (size_t d = 0; d < kN; ++d) {
        std::vector<double> diag(kN);
        for (size_t i = 0; i < kN; ++i) diag[i] = W[i][(i + d) % kN];
        auto ptxt_diag = cc->MakeCKKSPackedPlaintext(diag);
        auto ct_rot = cc->EvalRotate(x, static_cast<int32_t>(d));
        auto ct_term = cc->EvalMult(ct_rot, ptxt_diag);
        if (d == 0) {
            acc = ct_term;
        } else {
            acc = cc->EvalAdd(acc, ct_term);
        }
    }
    // All terms are at the same depth (one EvalMult each), so a single Rescale
    // after accumulation aligns the scale.
    return cc->Rescale(acc);
}

void medium_gen_keys(CryptoContext<DCRTPoly> cc, const KeyPair<DCRTPoly>& kp) {
    std::vector<int32_t> indices(kN);
    for (size_t i = 0; i < kN; ++i) indices[i] = static_cast<int32_t>(i);
    cc->EvalRotateKeyGen(kp.secretKey, indices);
}

}  // namespace

void register_medium(WorkloadRegistry& registry) {
    Workload w;
    w.make_context = make_medium_context;
    w.eval = medium_eval;
    w.gen_keys = medium_gen_keys;
    registry["medium"] = std::move(w);
}

}  // namespace tee
