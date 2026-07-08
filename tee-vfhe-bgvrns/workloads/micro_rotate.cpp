// BGV micro_rotate workload: ct_out = EvalRotate(ct, 1)
// Homomorphic left rotation of a BGV ciphertext by 1 position.
// Requires rotation (automorphism) keys for index 1 and -1.
// Self-registers into the global WorkloadRegistry at static init time.

#include "server/workload_registry.h"
#include "openfhe.h"

namespace {

using namespace lbcrypto;

tee::CC make_micro_rotate_context() {
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
    // ADVANCEDSHE is required for EvalRotateKeyGen / EvalAutomorphismKeyGen.
    cc->Enable(ADVANCEDSHE);
    return cc;
}

tee::CT micro_rotate_eval(tee::CC cc, const std::vector<tee::CT>& inputs) {
    if (inputs.size() != 1) {
        throw std::runtime_error("micro_rotate requires exactly 1 input ciphertext");
    }
    return cc->EvalRotate(inputs[0], 1);
}

// gen_keys hook: generate rotation keys for indices {1, -1}.
// EvalRotate(ct, 1) needs the rotation key for index 1; -1 is included
// for completeness (right rotation by 1).
void micro_rotate_gen_keys(tee::CC cc,
                           const lbcrypto::KeyPair<lbcrypto::DCRTPoly>& kp) {
    cc->EvalRotateKeyGen(kp.secretKey, {1, -1});
}

// Self-register at static initialization time.
[[maybe_unused]] tee::Register g_micro_rotate_reg("micro_rotate",
    tee::Workload{make_micro_rotate_context, micro_rotate_eval, micro_rotate_gen_keys});

}  // namespace
