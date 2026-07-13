// BGV noop workload: returns the first input ciphertext unchanged.
// Self-registers into the global WorkloadRegistry at static init time.

#include "server/workload_registry.h"
#include "common/baseline_params.h"
#include "openfhe.h"

namespace {

using namespace lbcrypto;

// noop uses the shared baseline BGV context (ring=8192, batch=4096, depth=4)
// so that the client-encrypted ciphertexts match the server's context
// exactly. The eval function simply returns its first input.
zk::CT noop_eval(zk::CC /*cc*/, const std::vector<zk::CT>& inputs) {
    if (inputs.empty()) {
        throw std::runtime_error("noop requires at least 1 input ciphertext");
    }
    return inputs[0];
}

// Self-register at static initialization time.
[[maybe_unused]] zk::Register g_noop_reg("noop",
    zk::Workload{make_baseline_bgvrns_context, noop_eval, nullptr});

}  // namespace