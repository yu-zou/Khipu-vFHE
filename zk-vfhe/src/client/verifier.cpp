#include "client/verifier.h"

#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp"
#include "libff/algebra/fields/bigint.hpp"

namespace zk {

namespace {

using pp = libsnark::default_r1cs_gg_ppzksnark_pp;
using FieldT = libff::Fr<pp>;

// Initialize libsnark public params once.
struct LibsnarkInit {
    LibsnarkInit() { pp::init_public_params(); }
};

void ensure_init() {
    static LibsnarkInit init;
    (void)init;
}

// Convert 32 bytes (big-endian) to a FieldT element.
FieldT bytes_to_field(const uint8_t* data) {
    libff::bigint<FieldT::num_limbs> b;
    // Clear limbs
    std::memset(b.data, 0, sizeof(b.data));

    // Copy 32 bytes in big-endian order into the bigint.
    // libff::bigint stores limbs as an array of uint64_t in little-endian
    // limb order but each limb is native. We load byte-by-byte from MSB.
    constexpr std::size_t num_bytes = 32;
    for (std::size_t i = 0; i < num_bytes; ++i) {
        std::size_t byte_idx = num_bytes - 1 - i;  // reverse for LE limb layout
        std::size_t limb_idx = i / 8;
        std::size_t shift = (i % 8) * 8;
        if (limb_idx < FieldT::num_limbs) {
            b.data[limb_idx] |= (static_cast<uint64_t>(data[byte_idx]) << shift);
        }
    }
    return FieldT(b);
}

}  // namespace

bool Verifier::verify_proof(const std::vector<uint8_t>& proof_bytes,
                            const std::vector<uint8_t>& public_inputs_bytes,
                            const std::vector<uint8_t>& vk_bytes) {
    try {
        ensure_init();

        // Deserialize verification key
        std::string vk_str(vk_bytes.begin(), vk_bytes.end());
        std::istringstream vk_iss(vk_str);
        libsnark::r1cs_gg_ppzksnark_verification_key<pp> vk;
        vk_iss >> vk;
        if (vk_iss.fail()) {
            std::cerr << "[verifier] failed to deserialize verification key" << std::endl;
            return false;
        }

        // Deserialize proof
        std::string proof_str(proof_bytes.begin(), proof_bytes.end());
        std::istringstream proof_iss(proof_str);
        libsnark::r1cs_gg_ppzksnark_proof<pp> proof;
        proof_iss >> proof;
        if (proof_iss.fail()) {
            std::cerr << "[verifier] failed to deserialize proof" << std::endl;
            return false;
        }

        // Deserialize public inputs: [num_inputs: uint32][field_element_1: 32 bytes]...
        if (public_inputs_bytes.size() < 4) {
            std::cerr << "[verifier] public_inputs_bytes too short" << std::endl;
            return false;
        }
        uint32_t num_inputs = 0;
        std::memcpy(&num_inputs, public_inputs_bytes.data(), sizeof(uint32_t));

        std::size_t expected_size = 4 + static_cast<std::size_t>(num_inputs) * 32;
        if (public_inputs_bytes.size() < expected_size) {
            std::cerr << "[verifier] public_inputs_bytes size mismatch: got "
                      << public_inputs_bytes.size() << " expected " << expected_size << std::endl;
            return false;
        }

        libsnark::r1cs_gg_ppzksnark_primary_input<pp> primary_input;
        for (uint32_t i = 0; i < num_inputs; ++i) {
            const uint8_t* elem_ptr = public_inputs_bytes.data() + 4 + static_cast<std::size_t>(i) * 32;
            primary_input.emplace_back(bytes_to_field(elem_ptr));
        }

        // Verify proof with strong input consistency
        bool valid = libsnark::r1cs_gg_ppzksnark_verifier_strong_IC(vk, primary_input, proof);
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
