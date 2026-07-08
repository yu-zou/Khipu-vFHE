// BGV noop workload: returns the first input ciphertext unchanged.
// Self-registers into the global WorkloadRegistry at static init time.

#include "server/workload_registry.h"
#include "openfhe.h"

namespace {

using namespace lbcrypto;

tee::CC make_noop_context() {
    CCParams<CryptoContextBGVRNS> params;
    params.SetMultiplicativeDepth(2);
    params.SetPlaintextModulus(65537);
    params.SetBatchSize(64);
    params.SetSecurityLevel(HEStd_128_classic);
    params.SetScalingTechnique(FIXEDMANUAL);
    params.SetKeySwitchTechnique(BV);
    params.SetDigitSize(4);
    params.SetFirstModSize(60);
    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    return cc;
}

tee::CT noop_eval(tee::CC /*cc*/, const std::vector<tee::CT>& inputs) {
    if (inputs.empty()) {
        throw std::runtime_error("noop requires at least 1 input ciphertext");
    }
    return inputs[0];
}

// Self-register at static initialization time.
[[maybe_unused]] tee::Register g_noop_reg("noop",
    tee::Workload{make_noop_context, noop_eval, nullptr});

}  // namespace