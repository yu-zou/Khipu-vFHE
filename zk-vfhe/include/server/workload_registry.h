#pragma once

#include <functional>
#include <map>
#include <string>
#include <vector>

#include "openfhe.h"

// Forward declaration; full type only needed in translation units that
// actually invoke the ZK eval function.
class LibsnarkProofSystem;

namespace zk {

using CT = lbcrypto::Ciphertext<lbcrypto::DCRTPoly>;
using CC = lbcrypto::CryptoContext<lbcrypto::DCRTPoly>;

struct Workload {
    std::function<CC()> make_context;
    std::function<CT(CC, const std::vector<CT>&)> eval;
    std::function<void(CC, const lbcrypto::KeyPair<lbcrypto::DCRTPoly>&)> gen_keys;
    // Optional: ZK eval using the zkOpenFHE ProofSystem API (ct-ct workloads).
    // When present, the server runs the three-pass constraint / witness / proof
    // pipeline after plain FHE evaluation and returns real proof bytes.
    std::function<CT(LibsnarkProofSystem&, std::vector<CT>&)> eval_zk;
};

using WorkloadRegistry = std::map<std::string, Workload>;

inline WorkloadRegistry& get_workload_registry() {
    static WorkloadRegistry registry;
    return registry;
}

inline void register_all_workloads() {
    (void)get_workload_registry();
}

struct Register {
    Register(const std::string& id, Workload w) {
        get_workload_registry().emplace(id, std::move(w));
    }
};

}  // namespace zk
