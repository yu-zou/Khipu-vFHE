// BGV micro_modswitch workload: ct_out = ModReduce(ct1)
// Applies BGV modulus reduction (drops one RNS tower limb) to a single ciphertext.
// In BGV, ModReduce preserves the plaintext value - it only reduces the ciphertext
// modulus chain by one level. This benchmarks the ModReduce operation in isolation.
// Self-registers into the global WorkloadRegistry at static init time.

#include "server/workload_registry.h"
#include "openfhe.h"

namespace {

using namespace lbcrypto;

tee::CC make_micro_modswitch_context() {
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

tee::CT micro_modswitch_eval(tee::CC cc, const std::vector<tee::CT>& inputs) {
    if (inputs.size() != 1) {
        throw std::runtime_error("micro_modswitch requires exactly 1 input ciphertext");
    }
    // ModReduce drops one RNS tower limb from the ciphertext modulus chain.
    // In BGV, this preserves the plaintext (mod t) because the operation
    // adjusts the ciphertext components to maintain the mod-t relationship.
    return cc->ModReduce(inputs[0]);
}

// Self-register at static initialization time.
// No gen_keys needed - ModReduce does not require evaluation keys.
[[maybe_unused]] tee::Register g_micro_modswitch_reg("micro_modswitch",
    tee::Workload{make_micro_modswitch_context, micro_modswitch_eval, nullptr});

}  // namespace
