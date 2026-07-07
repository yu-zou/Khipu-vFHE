// Workload "micro_add": ct_out = EvalAdd(ct1, ct2).
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

CryptoContext<DCRTPoly> make_micro_add_context() {
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

Ciphertext<DCRTPoly> micro_add_eval(CryptoContext<DCRTPoly> cc,
                                    const std::vector<Ciphertext<DCRTPoly>>& inputs) {
    (void)cc;
    if (inputs.size() != 2) {
        throw std::runtime_error("micro_add workload requires exactly 2 input ciphertexts");
    }
    return cc->EvalAdd(inputs[0], inputs[1]);
}

}  // namespace

void register_micro_add(WorkloadRegistry& registry) {
    Workload w;
    w.make_context = make_micro_add_context;
    w.eval = micro_add_eval;
    registry["micro_add"] = std::move(w);
}

}  // namespace tee
