#include "common/zk_proof.h"

// OpenFHE: base-scheme.h must come before proofsystem headers so that
// SchemeBase<DCRTPoly> is a complete type (not just forward-declared).
#include "schemebase/base-scheme.h"
#include "openfhe/pke/openfhe.h"
#include "openfhe/pke/scheme/bgvrns/bgvrns-ser.h"

#include <cstring>
#include <sstream>
#include <stdexcept>

#include "proofsystem/proofsystem_libsnark.h"

using libsnark::protoboard;
using libsnark::r1cs_constraint_system;
using libsnark::r1cs_primary_input;
using libsnark::r1cs_auxiliary_input;
using libsnark::r1cs_gg_ppzksnark_generator;
using libsnark::r1cs_gg_ppzksnark_prover;
using libsnark::r1cs_gg_ppzksnark_verifier_strong_IC;

namespace zk {

void generate_constraints(LibsnarkProofSystem& ps) {
    ps.SetMode(PROOFSYSTEM_MODE_CONSTRAINT_GENERATION);
}

void generate_witness(LibsnarkProofSystem& ps) {
    ps.SetMode(PROOFSYSTEM_MODE_WITNESS_GENERATION);
}

ProofBundle generate_proof(protoboard<FieldT>& pb) {
    r1cs_constraint_system<FieldT> cs = pb.get_constraint_system();
    r1cs_primary_input<FieldT> primary_input = pb.primary_input();
    r1cs_auxiliary_input<FieldT> auxiliary_input = pb.auxiliary_input();

    if (!cs.is_satisfied(primary_input, auxiliary_input)) {
        throw std::runtime_error("Constraint system is not satisfied");
    }

    auto keypair = r1cs_gg_ppzksnark_generator<pp>(cs);
    Proof proof = r1cs_gg_ppzksnark_prover<pp>(
        keypair.pk, primary_input, auxiliary_input);

    return ProofBundle{std::move(proof), std::move(primary_input),
                       std::move(keypair.vk)};
}

// ── Cached keypair (shared by setup/prove) ────────────────────────────────────

namespace {
    ProvingKey g_cached_pk;
    VerificationKey g_cached_vk;
    bool g_keypair_valid = false;
}  // namespace

VerificationKey setup(const ConstraintSystem& cs) {
    auto keypair = r1cs_gg_ppzksnark_generator<pp>(cs);
    g_cached_vk = std::move(keypair.vk);
    g_cached_pk = std::move(keypair.pk);
    g_keypair_valid = true;
    return g_cached_vk;
}

Proof prove(const PrimaryInput& primary_input,
            const AuxiliaryInput& auxiliary_input) {
    if (!g_keypair_valid) {
        throw std::runtime_error("Keypair not set up. Call setup() first.");
    }
    return r1cs_gg_ppzksnark_prover<pp>(
        g_cached_pk, primary_input, auxiliary_input);
}

bool verify_proof(const VerificationKey& vk,
                  const PrimaryInput& public_inputs,
                  const Proof& proof) {
    return r1cs_gg_ppzksnark_verifier_strong_IC<pp>(
        vk, public_inputs, proof);
}

std::vector<uint8_t> serialize_proof(const Proof& proof) {
    std::ostringstream oss(std::ios::binary);
    oss << proof;
    std::string s = oss.str();
    return std::vector<uint8_t>(s.begin(), s.end());
}

Proof deserialize_proof(const std::vector<uint8_t>& bytes) {
    Proof proof;
    std::string s(bytes.begin(), bytes.end());
    std::istringstream iss(s, std::ios::binary);
    iss >> proof;
    return proof;
}

std::vector<uint8_t> serialize_vk(const VerificationKey& vk) {
    std::ostringstream oss(std::ios::binary);
    oss << vk;
    std::string s = oss.str();
    return std::vector<uint8_t>(s.begin(), s.end());
}

VerificationKey deserialize_vk(const std::vector<uint8_t>& bytes) {
    VerificationKey vk;
    std::string s(bytes.begin(), bytes.end());
    std::istringstream iss(s, std::ios::binary);
    iss >> vk;
    return vk;
}

std::vector<uint8_t> serialize_pk(const ProvingKey& pk) {
    std::ostringstream oss(std::ios::binary);
    oss << pk;
    std::string s = oss.str();
    return std::vector<uint8_t>(s.begin(), s.end());
}

ProvingKey deserialize_pk(const std::vector<uint8_t>& bytes) {
    ProvingKey pk;
    std::string s(bytes.begin(), bytes.end());
    std::istringstream iss(s, std::ios::binary);
    iss >> pk;
    return pk;
}

std::vector<uint8_t> serialize_public_inputs(const PrimaryInput& inputs) {
    std::vector<uint8_t> result;
    uint32_t num_inputs = static_cast<uint32_t>(inputs.size());

    result.resize(4 + num_inputs * 32);
    result[0] = static_cast<uint8_t>((num_inputs >> 0) & 0xFF);
    result[1] = static_cast<uint8_t>((num_inputs >> 8) & 0xFF);
    result[2] = static_cast<uint8_t>((num_inputs >> 16) & 0xFF);
    result[3] = static_cast<uint8_t>((num_inputs >> 24) & 0xFF);

    size_t offset = 4;
    for (const auto& field_elem : inputs) {
        libff::bigint<FieldT::num_limbs> b = field_elem.as_bigint();
        // bigint uses stream operator<< for binary serialization (BINARY_OUTPUT mode)
        std::ostringstream oss(std::ios::binary);
        oss << b;
        std::string elem_bytes = oss.str();
        std::memcpy(result.data() + offset, elem_bytes.data(), 32);
        offset += 32;
    }

    return result;
}

PrimaryInput deserialize_public_inputs(const std::vector<uint8_t>& bytes) {
    if (bytes.size() < 4) {
        throw std::runtime_error("Invalid public inputs: too short");
    }

    uint32_t num_inputs = static_cast<uint32_t>(bytes[0])
                        | (static_cast<uint32_t>(bytes[1]) << 8)
                        | (static_cast<uint32_t>(bytes[2]) << 16)
                        | (static_cast<uint32_t>(bytes[3]) << 24);

    if (bytes.size() < 4 + static_cast<size_t>(num_inputs) * 32) {
        throw std::runtime_error("Invalid public inputs: size mismatch");
    }

    PrimaryInput inputs;
    inputs.reserve(num_inputs);

    size_t offset = 4;
    for (uint32_t i = 0; i < num_inputs; ++i) {
        libff::bigint<FieldT::num_limbs> b;
        std::string s(reinterpret_cast<const char*>(bytes.data() + offset), 32);
        std::istringstream iss(s, std::ios::binary);
        iss >> b;
        inputs.emplace_back(b);
        offset += 32;
    }

    return inputs;
}

}  // namespace zk
