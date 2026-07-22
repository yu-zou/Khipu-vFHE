#include "client/verifier.h"

#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "common/zk_proof.h"

// Must match the server-side snark: zkOpenFHE's LibsnarkProofSystem uses
// default_r1cs_ppzksnark_pp (PGHR13 over alt_bn128).
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
namespace zk {

namespace {

using pp = libsnark::default_r1cs_ppzksnark_pp;
// Initialize libsnark public params once.
struct LibsnarkInit {
    LibsnarkInit() { pp::init_public_params(); }
};

void ensure_init() {
    static LibsnarkInit init;
    (void)init;
}

}  // namespace

bool Verifier::verify_proof(const std::vector<uint8_t>& proof_bytes,
                            const std::vector<uint8_t>& public_inputs_bytes,
                            const std::vector<uint8_t>& vk_bytes) {
    try {
        ensure_init();

        if (proof_bytes.empty() || vk_bytes.empty()) {
            std::cerr << "[verifier] empty proof or vk" << std::endl;
            return false;
        }

        std::string vk_str(vk_bytes.begin(), vk_bytes.end());
        std::istringstream vk_iss(vk_str);
        libsnark::r1cs_ppzksnark_verification_key<pp> vk;
        vk_iss >> vk;
        if (vk_iss.fail()) {
            std::cerr << "[verifier] failed to deserialize verification key" << std::endl;
            return false;
        }

        std::string proof_str(proof_bytes.begin(), proof_bytes.end());
        std::istringstream proof_iss(proof_str);
        libsnark::r1cs_ppzksnark_proof<pp> proof;
        proof_iss >> proof;
        if (proof_iss.fail()) {
            std::cerr << "[verifier] failed to deserialize proof" << std::endl;
            return false;
        }

        auto primary_input = deserialize_public_inputs(public_inputs_bytes);
        bool valid = libsnark::r1cs_ppzksnark_verifier_strong_IC(vk, primary_input, proof);
        if (!valid) {
            std::cerr << "[verifier] ZK proof verification FAILED" << std::endl;
        }
        return valid;
    } catch (const std::exception& e) {
        std::cerr << "[verifier] verify_proof exception: " << e.what() << std::endl;
        return false;
    }
}

}  // namespace zk
