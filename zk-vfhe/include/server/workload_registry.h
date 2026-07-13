#pragma once

#include <functional>
#include <map>
#include <string>
#include <vector>

#include "openfhe.h"

namespace zk {

using CT = lbcrypto::Ciphertext<lbcrypto::DCRTPoly>;
using CC = lbcrypto::CryptoContext<lbcrypto::DCRTPoly>;

struct Workload {
    std::function<CC()> make_context;
    std::function<CT(CC, const std::vector<CT>&)> eval;
    std::function<void(CC, const lbcrypto::KeyPair<lbcrypto::DCRTPoly>&)> gen_keys;
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
