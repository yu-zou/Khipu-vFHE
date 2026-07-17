// Workload "toy": y = Rescale(c1 * c2)
// Inputs: 2 ciphertexts (length-32 vectors). Output: 1 ciphertext (length-32).
// depth=1, scaling=40, batch=32, FIXEDMANUAL, HEStd_128_classic. tol < 1e-4.

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

CryptoContext<DCRTPoly> make_toy_context() {
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

Ciphertext<DCRTPoly> toy_eval(CryptoContext<DCRTPoly> cc,
                              const std::vector<Ciphertext<DCRTPoly>>& inputs) {
    if (inputs.size() != 2) {
        throw std::runtime_error("toy workload requires exactly 2 input ciphertexts");
    }
    auto prod = cc->EvalMult(inputs[0], inputs[1]);
    return cc->Rescale(prod);
}

}  // namespace

Register g_toy("toy", {make_toy_context, toy_eval, nullptr});

}  // namespace tee
