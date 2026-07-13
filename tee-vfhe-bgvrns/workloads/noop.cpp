// BGV noop workload: returns the first input ciphertext unchanged.
// Self-registers into the global WorkloadRegistry at static init time.

#include "server/workload_registry.h"
#include "common/baseline_params.h"
#include "openfhe.h"

namespace {

using namespace lbcrypto;

// noop uses the shared baseline BGV context so that the client-encrypted
// ciphertexts match the server's context exactly (identical ringDim,
// batchSize, depth, and SecurityLevel).
tee::CT noop_eval(tee::CC /*cc*/, const std::vector<tee::CT>& inputs) {
    if (inputs.empty()) {
        throw std::runtime_error("noop requires at least 1 input ciphertext");
    }
    return inputs[0];
}

// Self-register at static initialization time.
[[maybe_unused]] tee::Register g_noop_reg("noop",
    tee::Workload{make_baseline_bgvrns_context, noop_eval, nullptr});

}  // namespace