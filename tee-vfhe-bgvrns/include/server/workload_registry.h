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

WorkloadRegistry& get_workload_registry();
void register_all_workloads();

}  // namespace tee