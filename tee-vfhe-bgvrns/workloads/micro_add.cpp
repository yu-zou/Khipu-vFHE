// BGV micro_add workload: ct_out = EvalAdd(ct1, ct2)
// Homomorphic addition of two BGV ciphertexts packing 64-slot integer vectors.
// Self-registers into the global WorkloadRegistry at static init time.

#include "server/workload_registry.h"
#include "openfhe.h"

namespace {

using namespace lbcrypto;

tee::CC make_micro_add_context() {
    CCParams<CryptoContextBGVRNS> params;
    params.SetMultiplicativeDepth(2);
    params.SetPlaintextModulus(65537);
    params.SetBatchSize(64);
    params.SetSecurityLevel(HEStd_128_classic);
    params.SetKeySwitchTechnique(BV);
    params.SetDigitSize(4);
    params.SetScalingTechnique(FIXEDMANUAL);
    params.SetFirstModSize(60);
    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    return cc;
}

tee::CT micro_add_eval(tee::CC cc, const std::vector<tee::CT>& inputs) {
    if (inputs.size() != 2) {
        throw std::runtime_error("micro_add requires exactly 2 input ciphertexts");
    }
    return cc->EvalAdd(inputs[0], inputs[1]);
}

// Self-register at static initialization time.
// No gen_keys needed - EvalAdd does not require special evaluation keys.
[[maybe_unused]] tee::Register g_micro_add_reg("micro_add",
    tee::Workload{make_micro_add_context, micro_add_eval, nullptr});

}  // namespace
