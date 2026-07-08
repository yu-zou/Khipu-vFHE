#pragma once

#include <functional>
#include <map>
#include <string>
#include <vector>

#include "openfhe.h"

namespace tee {

using CT = lbcrypto::Ciphertext<lbcrypto::DCRTPoly>;
using CC = lbcrypto::CryptoContext<lbcrypto::DCRTPoly>;

struct Workload {
    std::function<CC()> make_context;
    std::function<CT(CC, const std::vector<CT>&)> eval;
    // Optional hook: generates rotation/sum keys needed by eval. Default-empty
    // means only EvalMultKey (which the caller generates separately) is needed.
    std::function<void(CC, const lbcrypto::KeyPair<lbcrypto::DCRTPoly>&)> gen_keys;
};

using WorkloadRegistry = std::map<std::string, Workload>;

// Meyer's singleton: thread-safe, guaranteed initialized on first use.
// This avoids static initialization order issues between workload .cpp files
// and the registry itself.
inline WorkloadRegistry& get_workload_registry() {
    static WorkloadRegistry registry;
    return registry;
}

// Explicit registration function — a no-op when using static self-registration,
// but kept for code clarity and forward compatibility.
inline void register_all_workloads() {
    // Workloads self-register via static Register instances in each .cpp file.
    // This function exists so callers can explicitly trigger the pattern.
    // get_workload_registry() is already populated by the time main() runs.
    (void)get_workload_registry();
}

// Self-registration helper: construct one as a static variable in each workload
// .cpp file to register the workload at static initialization time.
struct Register {
    Register(const std::string& id, Workload w) {
        get_workload_registry().emplace(id, std::move(w));
    }
};

}  // namespace tee