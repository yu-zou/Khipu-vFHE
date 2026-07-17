#include "common/h100_evidence_adapter.h"

#include <nvat.h>
#include <cstring>
#include <iostream>
#include <stdexcept>

namespace tee {

std::vector<uint8_t> GpuEvidencePackage::serialize() const {
    std::vector<uint8_t> buf;
    auto write_blob = [&](const std::vector<uint8_t>& blob) {
        uint32_t sz = static_cast<uint32_t>(blob.size());
        buf.insert(buf.end(), reinterpret_cast<const uint8_t*>(&sz),
                   reinterpret_cast<const uint8_t*>(&sz) + 4);
        buf.insert(buf.end(), blob.begin(), blob.end());
    };
    write_blob(evidence_json);
    write_blob(detached_eat);
    write_blob(claims_json);
    buf.insert(buf.end(), nonce.begin(), nonce.end());
    return buf;
}

GpuEvidencePackage GpuEvidencePackage::deserialize(const std::vector<uint8_t>& data) {
    GpuEvidencePackage pkg;
    size_t offset = 0;
    auto read_blob = [&](std::vector<uint8_t>& blob) {
        if (offset + 4 > data.size()) throw std::runtime_error("deserialize: truncated");
        uint32_t sz;
        std::memcpy(&sz, data.data() + offset, 4);
        offset += 4;
        if (offset + sz > data.size()) throw std::runtime_error("deserialize: truncated blob");
        blob.assign(data.data() + offset, data.data() + offset + sz);
        offset += sz;
    };
    read_blob(pkg.evidence_json);
    read_blob(pkg.detached_eat);
    read_blob(pkg.claims_json);
    if (offset + 32 > data.size()) throw std::runtime_error("deserialize: truncated nonce");
    std::memcpy(pkg.nonce.data(), data.data() + offset, 32);
    return pkg;
}

H100EvidenceAdapter::~H100EvidenceAdapter() {
    if (initialized_) nvat_sdk_shutdown();
}

bool H100EvidenceAdapter::init() {
    if (initialized_) return true;

    nvat_sdk_opts_t opts = nullptr;
    nvat_rc_t rc = nvat_sdk_opts_create(&opts);
    if (rc != NVAT_OK) {
        std::cerr << "[h100] nvat_sdk_opts_create failed: " << nvat_rc_to_string(rc) << std::endl;
        return false;
    }

    rc = nvat_sdk_init(opts);
    nvat_sdk_opts_free(opts);
    if (rc != NVAT_OK) {
        std::cerr << "[h100] nvat_sdk_init failed: " << nvat_rc_to_string(rc) << std::endl;
        return false;
    }

    initialized_ = true;
    std::cerr << "[h100] NVTrust SDK initialized" << std::endl;
    return true;
}

GpuEvidencePackage H100EvidenceAdapter::collect_evidence(
    const std::array<uint8_t, 32>& nonce_bytes) {

    GpuEvidencePackage pkg;
    pkg.nonce = nonce_bytes;

    if (!initialized_) throw std::runtime_error("[h100] not initialized");

    nvat_rc_t rc;

    nvat_nonce_t nonce = nullptr;
    rc = nvat_nonce_from_bytes(&nonce,
        reinterpret_cast<const char*>(nonce_bytes.data()), nonce_bytes.size());
    if (rc != NVAT_OK) {
        throw std::runtime_error(std::string("[h100] nonce_from_bytes: ") + nvat_rc_to_string(rc));
    }

    nvat_gpu_evidence_source_t source = nullptr;
    rc = nvat_gpu_evidence_source_nvml_create(&source);
    if (rc != NVAT_OK) {
        nvat_nonce_free(&nonce);
        throw std::runtime_error(std::string("[h100] source_nvml_create: ") + nvat_rc_to_string(rc));
    }

    nvat_gpu_evidence_t* ev_arr = nullptr;
    size_t ev_count = 0;
    rc = nvat_gpu_evidence_collect(source, nonce, &ev_arr, &ev_count);
    nvat_gpu_evidence_source_free(&source);
    nvat_nonce_free(&nonce);

    if (rc != NVAT_OK) {
        throw std::runtime_error(std::string("[h100] evidence_collect: ") + nvat_rc_to_string(rc));
    }
    if (ev_count == 0 || !ev_arr) {
        throw std::runtime_error("[h100] no GPU evidence collected");
    }

    nvat_str_t ev_str = nullptr;
    rc = nvat_gpu_evidence_serialize_json(ev_arr, ev_count, &ev_str);
    nvat_gpu_evidence_array_free(&ev_arr, ev_count);
    if (rc != NVAT_OK) {
        throw std::runtime_error(std::string("[h100] serialize_json: ") + nvat_rc_to_string(rc));
    }

    char* str_data = nullptr;
    size_t str_len = 0;
    nvat_str_length(ev_str, &str_len);
    nvat_str_get_data(ev_str, &str_data);
    pkg.evidence_json.assign(str_data, str_data + str_len);
    nvat_str_free(&ev_str);

    std::cerr << "[h100] Collected GPU evidence: " << pkg.evidence_json.size() << " bytes" << std::endl;
    return pkg;
}

bool H100EvidenceAdapter::verify(const GpuEvidencePackage& evidence,
                                  const std::array<uint8_t, 32>& expected_nonce) {
    if (evidence.nonce != expected_nonce) {
        std::cerr << "[h100] nonce mismatch" << std::endl;
        return false;
    }
    if (evidence.evidence_json.empty()) {
        std::cerr << "[h100] evidence JSON empty" << std::endl;
        return false;
    }
    std::cerr << "[h100] GPU evidence basic verification passed" << std::endl;
    return true;
}

}  // namespace tee
