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

inline WorkloadRegistry& get_workload_registry() {
    static WorkloadRegistry registry;
    return registry;
}

struct Register {
    Register(const std::string& id, Workload w) {
        get_workload_registry().emplace(id, std::move(w));
    }
};

// Set the client's public key for FIDESlib GPU context initialization.
// Called by server_main after deserializing the client's public key.
void set_client_public_key(lbcrypto::PublicKey<lbcrypto::DCRTPoly> pk);

}  // namespace tee
