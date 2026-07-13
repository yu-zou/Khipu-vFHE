// BGV small_circuit workload: y = (c1*c2) + (c3*c4)
// 4 input ciphertexts, 2 ct-ct EvalMult, 1 ct-ct EvalAdd.
// Uses the shared baseline context (batchSize=4096, ringDim=8192, depth=4).
// CT-CT operations only — no rotations, no summation, no modulus reduction.

#include "common/baseline_params.h"
#include "server/workload_registry.h"
#include "openfhe.h"

namespace {

using namespace lbcrypto;

tee::CT small_eval(tee::CC cc, const std::vector<tee::CT>& inputs) {
    if (inputs.size() != 4) {
        throw std::runtime_error("small requires exactly 4 input ciphertexts");
    }
    const auto& c1 = inputs[0];
    const auto& c2 = inputs[1];
    const auto& c3 = inputs[2];
    const auto& c4 = inputs[3];

    auto u1 = cc->EvalMult(c1, c2);
    auto u2 = cc->EvalMult(c3, c4);
    return cc->EvalAdd(u1, u2);
}

[[maybe_unused]] tee::Register g_small_reg("small",
    tee::Workload{make_baseline_bgvrns_context, small_eval, nullptr});

}  // namespace
