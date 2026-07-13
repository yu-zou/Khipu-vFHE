// BGV-Add-4K workload: ct_out = EvalAdd(ct1, ct2)
// Homomorphic addition of two BGV ciphertexts packing 4096-slot integer vectors.
// Uses the shared baseline context (ringDim=8192, batchSize=4096, depth=4).
// Self-registers into the global WorkloadRegistry at static init time.

#include "common/baseline_params.h"
#include "server/workload_registry.h"
#include "openfhe.h"

namespace {

using namespace lbcrypto;

tee::CT bgv_add_4k_eval(tee::CC cc, const std::vector<tee::CT>& inputs) {
    if (inputs.size() != 2) {
        throw std::runtime_error("BGV-Add-4K requires exactly 2 input ciphertexts");
    }
    return cc->EvalAdd(inputs[0], inputs[1]);
}

// Self-register at static initialization time.
// Uses the shared baseline context (batchSize=4096, ringDim=8192, depth=4).
// No gen_keys needed - EvalAdd does not require special evaluation keys.
[[maybe_unused]] tee::Register g_bgv_add_4k_reg("BGV-Add-4K",
    tee::Workload{make_baseline_bgvrns_context, bgv_add_4k_eval, nullptr});

}  // namespace
