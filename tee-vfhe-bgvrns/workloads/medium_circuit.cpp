// BGV medium_circuit workload: y = (c1*c2) + (c3*c4) + (c5*c6)
// 6 input ciphertexts, 3 ct-ct EvalMult (parallel), 2 ct-ct EvalAdd.
// Uses the shared baseline context (batchSize=4096, ringDim=8192, depth=4).
//
// NOTE: The original medium formula was y = ((c1*c2)+(c3*c4)) * (c5*c6) which
// has multiplicative depth 2. That requires Relinearize between the first and
// second multiplication levels (the 3-element product must be relinearized to
// 2 elements before another EvalMultNoRelin). zkOpenFHE's RelinearizeConstraint
// is buggy (the relin unit test crashes, and it produces unsatisfied constraint
// systems at production scale), so we flattened the circuit to depth 1: three
// parallel multiplications summed together. This preserves 3 ct-ct mults while
// avoiding the need for Relinearize in the ZK pipeline. E uses the same flattened
// circuit to preserve circuit parity for a fair E vs. B comparison.
//
// Uses EvalMultNoRelin (no relinearization). See toy.cpp for the rationale.

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

    auto u1   = cc->EvalMultNoRelin(c1, c2);
    auto u2   = cc->EvalMultNoRelin(c3, c4);
    auto u3   = cc->EvalMultNoRelin(c5, c6);
    auto sum  = cc->EvalAdd(u1, u2);
    return cc->EvalAdd(sum, u3);
}

[[maybe_unused]] tee::Register g_medium_reg("medium",
    tee::Workload{make_baseline_bgvrns_context, medium_eval, nullptr});

}  // namespace
