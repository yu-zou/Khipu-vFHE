#pragma once

#include <cstdint>
#include <vector>

namespace zk {

class Verifier {
public:
    // Verify a ZK proof against a verification key and public inputs.
    // proof_bytes: serialized r1cs_gg_ppzksnark_proof (via operator<<)
    // public_inputs_bytes: [num_inputs: uint32][field_element_1: 32 bytes]...
    // vk_bytes: serialized r1cs_gg_ppzksnark_verification_key (via operator<<)
    bool verify_proof(const std::vector<uint8_t>& proof_bytes,
                      const std::vector<uint8_t>& public_inputs_bytes,
                      const std::vector<uint8_t>& vk_bytes);
};

}  // namespace zk
