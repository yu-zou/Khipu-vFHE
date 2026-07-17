#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace tee {

struct GpuEvidencePackage {
    std::vector<uint8_t> evidence_json;
    std::vector<uint8_t> detached_eat;
    std::vector<uint8_t> claims_json;
    std::array<uint8_t, 32> nonce{};

    std::vector<uint8_t> serialize() const;
    static GpuEvidencePackage deserialize(const std::vector<uint8_t>& data);
};

class H100EvidenceAdapter {
public:
    H100EvidenceAdapter() = default;
    ~H100EvidenceAdapter();

    bool init();
    GpuEvidencePackage collect_evidence(const std::array<uint8_t, 32>& nonce);
    bool verify(const GpuEvidencePackage& evidence,
                const std::array<uint8_t, 32>& expected_nonce);
    bool is_ready() const { return initialized_; }

private:
    bool initialized_ = false;
};

}  // namespace tee
