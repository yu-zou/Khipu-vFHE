#ifndef ZK_VFE_INCLUDE_COMMON_ZK_PROOF_H
#define ZK_VFE_INCLUDE_COMMON_ZK_PROOF_H

#include <cstdint>
#include <vector>

// zkOpenFHE's LibsnarkProofSystem builds its protoboard against
// default_r1cs_ppzksnark_pp (PGHR13-style ppzkSNARK over alt_bn128), so all
// constraint-system / proof types here must use the same curve parameters.
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"
#include "libff/algebra/fields/field_utils.hpp"

// Forward declaration to avoid pulling full CryptoContextImpl template instantiation
class LibsnarkProofSystem;

namespace zk {

using pp = libsnark::default_r1cs_ppzksnark_pp;
using FieldT = libff::Fr<pp>;
using Proof = libsnark::r1cs_ppzksnark_proof<pp>;
using VerificationKey = libsnark::r1cs_ppzksnark_verification_key<pp>;
using ProvingKey = libsnark::r1cs_ppzksnark_proving_key<pp>;
using Keypair = libsnark::r1cs_ppzksnark_keypair<pp>;
using ConstraintSystem = libsnark::r1cs_ppzksnark_constraint_system<pp>;
using PrimaryInput = libsnark::r1cs_ppzksnark_primary_input<pp>;
using AuxiliaryInput = libsnark::r1cs_ppzksnark_auxiliary_input<pp>;

struct ProofBundle {
    Proof proof;
    PrimaryInput public_inputs;
    VerificationKey vk;
};

void generate_constraints(LibsnarkProofSystem& ps);
void generate_witness(LibsnarkProofSystem& ps);
ProofBundle generate_proof(libsnark::protoboard<FieldT>& pb);

// Cached keypair API: call setup() once per constraint system, prove() per request.
VerificationKey setup(const ConstraintSystem& cs);
Proof prove(const PrimaryInput& primary_input, const AuxiliaryInput& auxiliary_input);

// Release the cached proving/verification key and return memory to the OS.
// Call between unrelated proofs to prevent unbounded memory growth when
// the server processes multiple workloads with different constraint systems.
void clear_cached_keypair();

bool verify_proof(const VerificationKey& vk,
                  const PrimaryInput& public_inputs,
                  const Proof& proof);

std::vector<uint8_t> serialize_proof(const Proof& proof);
Proof deserialize_proof(const std::vector<uint8_t>& bytes);

std::vector<uint8_t> serialize_vk(const VerificationKey& vk);
VerificationKey deserialize_vk(const std::vector<uint8_t>& bytes);

std::vector<uint8_t> serialize_pk(const ProvingKey& pk);
ProvingKey deserialize_pk(const std::vector<uint8_t>& bytes);

std::vector<uint8_t> serialize_public_inputs(const PrimaryInput& inputs);
PrimaryInput deserialize_public_inputs(const std::vector<uint8_t>& bytes);

}  // namespace zk

#endif  // ZK_VFE_INCLUDE_COMMON_ZK_PROOF_H
