// Workload "micro_rotate": ct_out = EvalRotate(ct, 1).
// Inputs: 1 ciphertext. Output: 1 ciphertext. depth=1, scaling=40, batch=32,
// FIXEDMANUAL, HEStd_128_classic. tol < 1e-5. gen_keys: EvalRotateKeyGen {1}.

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

CryptoContext<DCRTPoly> make_micro_rotate_context() {
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

Ciphertext<DCRTPoly> micro_rotate_eval(
    CryptoContext<DCRTPoly> cc,
    const std::vector<Ciphertext<DCRTPoly>>& inputs) {
    if (inputs.size() != 1) {
        throw std::runtime_error("micro_rotate workload requires exactly 1 input ciphertext");
    }
    return cc->EvalRotate(inputs[0], 1);
}

void micro_rotate_gen_keys(CryptoContext<DCRTPoly> cc, const KeyPair<DCRTPoly>& kp) {
    cc->EvalRotateKeyGen(kp.secretKey, {1});
}

}  // namespace

// Self-register the micro_rotate workload
static Register g_micro_rotate_reg("micro_rotate", Workload{make_micro_rotate_context, micro_rotate_eval, micro_rotate_gen_keys});

}  // namespace tee
