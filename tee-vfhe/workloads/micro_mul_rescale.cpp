// Workload "micro_mul_rescale": ct_out = Rescale(EvalMult(ct1, ct2)).
// Inputs: 2 ciphertexts. Output: 1 ciphertext. depth=1, scaling=40, batch=32,
// FIXEDMANUAL, HEStd_128_classic. tol < 1e-4. No extra keys.

#include "server/workload_registry.h"

#include <stdexcept>
#include <vector>

#include "openfhe.h"
#include "openfhe/pke/cryptocontext-ser.h"
#include "openfhe/pke/key/key-ser.h"
#include "openfhe/pke/scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;

namespace tee {
namespace {

CryptoContext<DCRTPoly> make_micro_mul_rescale_context() {
    CCParams<CryptoContextCKKSRNS> params;
    params.SetMultiplicativeDepth(1);
    params.SetScalingModSize(40);
    params.SetBatchSize(32);
    params.SetScalingTechnique(FIXEDMANUAL);
    params.SetSecurityLevel(HEStd_128_classic);
    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    return cc;
}

Ciphertext<DCRTPoly> micro_mul_rescale_eval(
    CryptoContext<DCRTPoly> cc,
    const std::vector<Ciphertext<DCRTPoly>>& inputs) {
    if (inputs.size() != 2) {
        throw std::runtime_error("micro_mul_rescale workload requires exactly 2 input ciphertexts");
    }
    auto prod = cc->EvalMult(inputs[0], inputs[1]);
    return cc->Rescale(prod);
}

}  // namespace

// Self-register the micro_mul_rescale workload
static Register g_micro_mul_rescale_reg("micro_mul_rescale", Workload{make_micro_mul_rescale_context, micro_mul_rescale_eval});

}  // namespace tee
