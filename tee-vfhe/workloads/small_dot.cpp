// Workload "small": y = sum_i w_i * x_i for i=1..32 (dot product).
// Inputs: 1 ciphertext (length-32 vector x). Output: 1 ciphertext (scalar in
// slot 0, broadcast). depth=2, scaling=40, batch=32, FIXEDMANUAL,
// HEStd_128_classic. tol < 1e-3. gen_keys: EvalSumKeyGen.

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

// Fixed deterministic weights (seed 42, uniform [-1, 1]). Generated once and
// embedded so benchmarks are reproducible.
std::vector<double> make_small_weights() {
    std::mt19937 gen(42);
    std::uniform_real_distribution<double> dist(-1.0, 1.0);
    std::vector<double> w(32);
    for (size_t i = 0; i < 32; ++i) w[i] = dist(gen);
    return w;
}

CryptoContext<DCRTPoly> make_small_context() {
    CCParams<CryptoContextCKKSRNS> params;
    params.SetMultiplicativeDepth(2);
    params.SetScalingModSize(40);
    params.SetBatchSize(32);
    params.SetScalingTechnique(FIXEDMANUAL);
    params.SetSecurityLevel(HEStd_128_classic);
    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);  // required for EvalSum / EvalSumKeyGen
    return cc;
}

Ciphertext<DCRTPoly> small_eval(CryptoContext<DCRTPoly> cc,
                                const std::vector<Ciphertext<DCRTPoly>>& inputs) {
    if (inputs.size() != 1) {
        throw std::runtime_error("small workload requires exactly 1 input ciphertext");
    }
    auto w = make_small_weights();
    auto ptxt_w = cc->MakeCKKSPackedPlaintext(w);
    auto ct_prod = cc->EvalMult(inputs[0], ptxt_w);
    auto ct_rescaled = cc->Rescale(ct_prod);
    // EvalSum across batchSize slots collapses all slot products into slot 0.
    auto ct_sum = cc->EvalSum(ct_rescaled, 32);
    return ct_sum;
}

void small_gen_keys(CryptoContext<DCRTPoly> cc, const KeyPair<DCRTPoly>& kp) {
    cc->EvalSumKeyGen(kp.secretKey);
}

}  // namespace

// Self-register the small workload
static Register g_small_reg("small", Workload{make_small_context, small_eval, small_gen_keys});

}  // namespace tee
