// BGV medium_circuit workload: y = ((c1*c2) + (c3*c4)) * (c5*c6)
// 6 input ciphertexts, 3 ct-ct EvalMult, 1 ct-ct EvalAdd, 1 ct-ct EvalMult.
// Uses the shared baseline context (batchSize=4096, ringDim=8192, depth=4).
// CT-CT operations only — no rotations, no summation, no modulus reduction.

#include "common/baseline_params.h"
#include "server/workload_registry.h"
#include "openfhe.h"

namespace {

using namespace lbcrypto;

tee::CT medium_eval(tee::CC cc, const std::vector<tee::CT>& inputs) {
    if (inputs.size() != 6) {
        throw std::runtime_error("medium requires exactly 6 input ciphertexts");
    }
    const auto& c1 = inputs[0];
    const auto& c2 = inputs[1];
    const auto& c3 = inputs[2];
    const auto& c4 = inputs[3];
    const auto& c5 = inputs[4];
    const auto& c6 = inputs[5];

    auto u1   = cc->EvalMult(c1, c2);
    auto u2   = cc->EvalMult(c3, c4);
    auto u3   = cc->EvalMult(c5, c6);
    auto sum  = cc->EvalAdd(u1, u2);
    return cc->EvalMult(sum, u3);
}

[[maybe_unused]] tee::Register g_medium_reg("medium",
    tee::Workload{make_baseline_bgvrns_context, medium_eval, nullptr});

}  // namespace
