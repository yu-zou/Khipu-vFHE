// BGV small_circuit workload: y = (c1*c2) + (c3*c4)
// 4 input ciphertexts, 2 ct-ct EvalMult, 1 ct-ct EvalAdd.
// Uses the shared baseline context (batchSize=4096, ringDim=8192, depth=4).
// CT-CT operations only - no rotations, no summation, no modulus reduction.
//
// NOTE: Uses EvalMultNoRelin (no relinearization) in both eval and eval_zk.
// See toy.cpp for the rationale (zkOpenFHE RelinearizeConstraint is buggy).

#include "common/baseline_params.h"
#include "server/workload_registry.h"
#include "openfhe.h"
#include "proofsystem/proofsystem_libsnark.h"

namespace {

using namespace lbcrypto;

zk::CT small_eval(zk::CC cc, const std::vector<zk::CT>& inputs) {
    if (inputs.size() != 4) {
        throw std::runtime_error("small requires exactly 4 input ciphertexts");
    }
    const auto& c1 = inputs[0];
    const auto& c2 = inputs[1];
    const auto& c3 = inputs[2];
    const auto& c4 = inputs[3];

    auto u1 = cc->EvalMultNoRelin(c1, c2);
    auto u2 = cc->EvalMultNoRelin(c3, c4);
    return cc->EvalAdd(u1, u2);
}

zk::CT small_eval_zk(LibsnarkProofSystem& ps, std::vector<zk::CT>& inputs) {
    if (inputs.size() != 4) {
        throw std::runtime_error("small requires exactly 4 input ciphertexts");
    }
    for (auto& ct : inputs) ps.PublicInput(ct);
    auto u1 = ps.EvalMultNoRelin(inputs[0], inputs[1]);
    auto u2 = ps.EvalMultNoRelin(inputs[2], inputs[3]);
    return ps.EvalAdd(u1, u2);
}

[[maybe_unused]] zk::Register g_small_reg("small",
    zk::Workload{make_baseline_bgvrns_context, small_eval, nullptr, small_eval_zk});

}  // namespace
