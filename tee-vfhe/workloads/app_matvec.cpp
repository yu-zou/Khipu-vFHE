// Workload "app_matvec": y = A * x, A is 256x256 dense float64 matrix.
// Inputs: 1 ciphertext (length-256 vector x). Output: length-256 vector ciphertext.
// depth=4, scaling=50, batch=256, FIXEDMANUAL, HEStd_128_classic. tol < 1e-1.
// gen_keys: EvalRotateKeyGen indices {0..255}. Diagonal method, final Rescale.

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

constexpr size_t kN = 256;

// Fixed deterministic 256x256 matrix A (seed 42, uniform [-1, 1]). Generated
// per-call but cheap; never materialized as individual plaintexts.
std::vector<std::vector<double>> make_app_matrix() {
    std::mt19937 gen(42);
    std::uniform_real_distribution<double> dist(-1.0, 1.0);
    std::vector<std::vector<double>> A(kN, std::vector<double>(kN));
    for (size_t i = 0; i < kN; ++i)
        for (size_t j = 0; j < kN; ++j) A[i][j] = dist(gen);
    return A;
}

CryptoContext<DCRTPoly> make_app_matvec_context() {
    CCParams<CryptoContextCKKSRNS> params;
    params.SetMultiplicativeDepth(4);
    params.SetScalingModSize(50);
    params.SetBatchSize(kN);
    params.SetScalingTechnique(FIXEDMANUAL);
    params.SetSecurityLevel(HEStd_128_classic);
    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    return cc;
}

Ciphertext<DCRTPoly> app_matvec_eval(CryptoContext<DCRTPoly> cc,
                                     const std::vector<Ciphertext<DCRTPoly>>& inputs) {
    if (inputs.size() != 1) {
        throw std::runtime_error("app_matvec workload requires exactly 1 input ciphertext");
    }
    auto A = make_app_matrix();
    const auto& x = inputs[0];

    // Diagonal method: result = sum_{d=0}^{N-1} diag_d \odot rot(x, d)
    // where diag_d[i] = A[i][(i+d) % N]. One diagonal at a time keeps peak
    // memory bounded by O(N) per iteration (single plaintext + ciphertext).
    Ciphertext<DCRTPoly> acc;
    for (size_t d = 0; d < kN; ++d) {
        std::vector<double> diag(kN);
        for (size_t i = 0; i < kN; ++i) diag[i] = A[i][(i + d) % kN];
        auto ptxt_diag = cc->MakeCKKSPackedPlaintext(diag);
        auto ct_rot = cc->EvalRotate(x, static_cast<int32_t>(d));
        auto ct_term = cc->EvalMult(ct_rot, ptxt_diag);
        if (d == 0) {
            acc = ct_term;
        } else {
            acc = cc->EvalAdd(acc, ct_term);
        }
    }
    // All terms are at depth 1 (one EvalMult); single Rescale aligns scale.
    return cc->Rescale(acc);
}

void app_matvec_gen_keys(CryptoContext<DCRTPoly> cc, const KeyPair<DCRTPoly>& kp) {
    std::vector<int32_t> indices(kN);
    for (size_t i = 0; i < kN; ++i) indices[i] = static_cast<int32_t>(i);
    cc->EvalRotateKeyGen(kp.secretKey, indices);
}

}  // namespace

void register_app_matvec(WorkloadRegistry& registry) {
    Workload w;
    w.make_context = make_app_matvec_context;
    w.eval = app_matvec_eval;
    w.gen_keys = app_matvec_gen_keys;
    registry["app_matvec"] = std::move(w);
}

}  // namespace tee
