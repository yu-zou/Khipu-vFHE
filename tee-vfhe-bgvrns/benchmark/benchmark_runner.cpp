// BGV benchmark runner: connects to the BGV TDX-vFHE server, runs every
// registered workload end-to-end, and emits a CSV of timing + size metrics
// to stdout. Diagnostics go to stderr so they never corrupt the CSV.
//
// Usage: benchmark_runner [--host HOST] [--port PORT] [--expected-mr-td HEX]

#include <sys/resource.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "client/verifier.h"
#include "common/attestation.h"
#include "common/hashing.h"
#include "common/serialization.h"
#include "common/tcp_transport.h"
#include "openfhe.h"
#include "openfhe/pke/cryptocontext-ser.h"
#include "openfhe/pke/key/key-ser.h"
#include "openfhe/pke/scheme/bgvrns/bgvrns-ser.h"
#include "server/workload_registry.h"

using namespace tee;
using namespace lbcrypto;

namespace {

struct WorkloadSpec {
    std::string id;
    int num_inputs;
    int slots;
    int seed_a;
    int seed_b;
};

// Deterministic input-generation metadata. Matches client_main.cpp kWorkloads.
// Standard workloads use 64 slots; E workloads use 4096 slots (batchSize=4096,
// ringDim=8192) via the shared baseline context.
const std::vector<WorkloadSpec> kWorkloads = {
    {"noop",            1, 64,   42,   0},
    {"toy",             2, 64,   42, 123},
    {"small",           4, 64,   42, 123},
    {"medium",          6, 64,   42, 123},
    {"BGV-Add-4K",      2, 4096, 42, 123},
    {"BGV-Mul-4K",      2, 4096, 42, 123},
};

// ── Wire-format helpers (same framing as Prototype A / BGV client) ─────────────

class BufWriter {
public:
    void write_u32_be(uint32_t v) {
        uint8_t b[4] = {uint8_t(v >> 24), uint8_t(v >> 16),
                        uint8_t(v >> 8), uint8_t(v)};
        buf_.insert(buf_.end(), b, b + 4);
    }
    void write_blob(const std::vector<uint8_t>& v) {
        uint64_t n64 = v.size();
        uint8_t len_bytes[8];
        for (int i = 7; i >= 0; i--) { len_bytes[i] = n64 & 0xFF; n64 >>= 8; }
        buf_.insert(buf_.end(), len_bytes, len_bytes + 8);
        buf_.insert(buf_.end(), v.begin(), v.end());
    }
    void write_string(const std::string& s) {
        write_blob(std::vector<uint8_t>(s.begin(), s.end()));
    }
    const std::vector<uint8_t>& data() const { return buf_; }
private:
    std::vector<uint8_t> buf_;
};

class BufReader {
public:
    explicit BufReader(const std::vector<uint8_t>& buf) : buf_(buf), pos_(0) {}
    const uint8_t* read(size_t n) {
        if (pos_ + n > buf_.size()) throw std::runtime_error("response truncated");
        const uint8_t* p = buf_.data() + pos_;
        pos_ += n;
        return p;
    }
    uint32_t read_u32_be() {
        const uint8_t* p = read(4);
        return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
               (uint32_t(p[2]) << 8) | uint32_t(p[3]);
    }
    std::vector<uint8_t> read_blob() {
        uint8_t len_bytes[8];
        std::memcpy(len_bytes, buf_.data() + pos_, 8);
        pos_ += 8;
        uint64_t n = 0;
        for (int i = 0; i < 8; i++) { n = (n << 8) | len_bytes[i]; }
        const uint8_t* p = read(n);
        return std::vector<uint8_t>(p, p + n);
    }
    std::string read_string() {
        auto v = read_blob();
        return std::string(v.begin(), v.end());
    }
    size_t remaining() const { return buf_.size() - pos_; }
private:
    const std::vector<uint8_t>& buf_;
    size_t pos_;
};

// ── Helpers ───────────────────────────────────────────────────────────────────

std::vector<uint8_t> random_nonce(size_t n) {
    std::vector<uint8_t> out(n);
    std::ifstream ur("/dev/urandom", std::ios::binary);
    if (ur) {
        ur.read(reinterpret_cast<char*>(out.data()),
                static_cast<std::streamsize>(n));
    }
    if (!ur || ur.gcount() != static_cast<std::streamsize>(n)) {
        for (size_t i = 0; i < n; ++i) out[i] = static_cast<uint8_t>(i * 31u + 7u);
    }
    return out;
}

Hash32 hash_concatenated(const std::vector<std::vector<uint8_t>>& parts) {
    std::vector<uint8_t> buf;
    size_t total = 0;
    for (const auto& p : parts) total += p.size();
    buf.reserve(total);
    for (const auto& p : parts) buf.insert(buf.end(), p.begin(), p.end());
    return blake3_hash(buf);
}

// BGV input: integer values in [0, plaintextModulus). Matches client_main.cpp.
std::vector<int64_t> gen_input_vec(int slots, int seed) {
    std::mt19937 gen(seed);
    std::uniform_int_distribution<int64_t> dist(0, 65536);
    std::vector<int64_t> vals(slots);
    for (int i = 0; i < slots; ++i) vals[i] = dist(gen);
    return vals;
}

std::vector<std::vector<uint8_t>> serialize_all_eval_keys(const CC& cc) {
    // Always emit 3 blobs in order: [EvalMultKey, EvalSumKey, EvalAutomorphismKey].
    // Empty blobs are sent as zero-length vectors so the server can unambiguously
    // deserialize by index.
    std::vector<std::vector<uint8_t>> blobs(3);
    {
        std::ostringstream oss(std::ios::binary);
        if (CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey(oss, SerType::BINARY, cc)) {
            std::string s = oss.str();
            blobs[0] = std::vector<uint8_t>(s.begin(), s.end());
        }
    }
    {
        std::ostringstream oss(std::ios::binary);
        if (CryptoContextImpl<DCRTPoly>::SerializeEvalSumKey(oss, SerType::BINARY, cc)) {
            std::string s = oss.str();
            blobs[1] = std::vector<uint8_t>(s.begin(), s.end());
        }
    }
    {
        std::ostringstream oss(std::ios::binary);
        if (CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey(oss, SerType::BINARY, cc)) {
            std::string s = oss.str();
            blobs[2] = std::vector<uint8_t>(s.begin(), s.end());
        }
    }
    return blobs;
}

long get_peak_mem_kb() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    return usage.ru_maxrss;
}

void print_usage(const char* argv0) {
    std::cerr << "Usage: " << argv0
              << " [--host HOST] [--port PORT] [--expected-mr-td HEX]"
              << std::endl;
}

}  // namespace

int main(int argc, char** argv) {
    std::string host = "127.0.0.1";
    uint16_t port = 8080;
    std::string expected_mr_td;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--host" && i + 1 < argc) {
            host = argv[++i];
        } else if (a == "--port" && i + 1 < argc) {
            port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (a == "--expected-mr-td" && i + 1 < argc) {
            expected_mr_td = argv[++i];
        } else if (a == "--help" || a == "-h") {
            print_usage(argv[0]);
            return 0;
        } else {
            std::cerr << "Unknown argument: " << a << std::endl;
            print_usage(argv[0]);
            return 1;
        }
    }

    register_all_workloads();
    const auto& registry = get_workload_registry();

    // CSV header + rows go to stdout; everything else to stderr.
    std::cout << "workload,server_e2e_us,client_us,input_loading_us,fhe_eval_us,"
                 "transcript_us,quote_us,packaging_us,verify_us,peak_mem_kb,"
                 "transcript_bytes,quote_bytes\n";

    bool all_ok = true;
    for (const auto& spec : kWorkloads) {
        std::cerr << "[benchmark] running workload: " << spec.id << std::endl;

        auto it = registry.find(spec.id);
        if (it == registry.end()) {
            std::cerr << "[benchmark] unknown workload: " << spec.id
                      << " (skipping)" << std::endl;
            all_ok = false;
            continue;
        }
        const Workload& workload = it->second;

        try {
            // Clear globally-accumulated eval keys from previous workloads.
            CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
            CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
            CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();

            auto t_prep_start = std::chrono::steady_clock::now();
            auto cc = workload.make_context();
            auto kp = cc->KeyGen();

            if (workload.gen_keys) {
                workload.gen_keys(cc, kp);
            }
            cc->EvalMultKeyGen(kp.secretKey);

            std::vector<std::vector<uint8_t>> eval_keys =
                serialize_all_eval_keys(cc);

            std::vector<uint8_t> nonce = random_nonce(16);

            // Encrypt deterministic BGV inputs.
            std::vector<std::vector<uint8_t>> input_ct_blobs;
            for (int i = 0; i < spec.num_inputs; ++i) {
                int seed = spec.seed_a + i * spec.seed_b;
                auto vals = gen_input_vec(spec.slots, seed);
                auto pt = cc->MakePackedPlaintext(vals);
                auto ct = cc->Encrypt(kp.publicKey, pt);
                std::string s = serialize_ciphertext(ct);
                input_ct_blobs.emplace_back(s.begin(), s.end());
            }

            // Build request: nonce, eval-key count + blobs, input-ct count +
            // blobs, workload-id string.
            BufWriter w;
            w.write_blob(nonce);
            w.write_u32_be(static_cast<uint32_t>(eval_keys.size()));
            for (const auto& k : eval_keys) w.write_blob(k);
            w.write_u32_be(static_cast<uint32_t>(input_ct_blobs.size()));
            for (const auto& c : input_ct_blobs) w.write_blob(c);
            w.write_string(spec.id);

            auto t_prep_end = std::chrono::steady_clock::now();
            auto t_round_trip_start = std::chrono::steady_clock::now();
            TCPClient cli(host, port);
            send_message(cli.fd(), w.data());
            auto resp = recv_message(cli.fd());
            cli.close();
            auto t_round_trip_end = std::chrono::steady_clock::now();

            if (resp.empty()) {
                std::cerr << "[benchmark] " << spec.id << ": empty response"
                          << std::endl;
                all_ok = false;
                continue;
            }

            BufReader rr(resp);
            auto output_ct_bytes = rr.read_blob();
            auto transcript_json = rr.read_string();
            auto quote_bytes = rr.read_blob();
            if (rr.remaining() != 0) {
                std::cerr << "[benchmark] " << spec.id
                          << ": trailing bytes in response" << std::endl;
                all_ok = false;
                continue;
            }

            if (transcript_json.find("\"error\"") != std::string::npos) {
                std::cerr << "[benchmark] " << spec.id << ": server error: "
                          << transcript_json << std::endl;
                all_ok = false;
                continue;
            }

            Transcript transcript = Transcript::from_json(transcript_json);

            Hash32 expected_eval_key_hash = hash_concatenated(eval_keys);
            std::vector<Hash32> expected_input_ct_hashes;
            expected_input_ct_hashes.reserve(input_ct_blobs.size());
            for (const auto& cb : input_ct_blobs) {
                expected_input_ct_hashes.push_back(blake3_hash(cb));
            }
            Hash32 expected_output_ct_hash = blake3_hash(output_ct_bytes);

            auto t_verify_start = std::chrono::steady_clock::now();
            Verifier verifier;
            bool ok = verifier.verify_all(
                quote_bytes, transcript, nonce, expected_mr_td,
                expected_eval_key_hash, expected_input_ct_hashes,
                expected_output_ct_hash);
            auto t_verify_end = std::chrono::steady_clock::now();

            if (!ok) {
                std::cerr << "[benchmark] " << spec.id
                          << ": attestation verification FAILED (continuing)"
                          << std::endl;
            }

            uint64_t round_trip_us = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    t_round_trip_end - t_round_trip_start).count());
            uint64_t request_prep_us = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    t_prep_end - t_prep_start).count());
            uint64_t verify_us = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    t_verify_end - t_verify_start).count());

            // Extract additional metrics from transcript JSON.
            nlohmann::json tj = nlohmann::json::parse(transcript_json);
            uint64_t input_loading_us = tj.value("input_loading_us", 0ULL);
            uint64_t packaging_us = tj.value("packaging_us", 0ULL);
            uint64_t json_peak_mem_kb = tj.value("peak_mem_kb", 0ULL);

            // Server-side E2E = sum of all server-reported phases.
            uint64_t server_e2e_us = input_loading_us + transcript.fhe_eval_us
                + transcript.transcript_us + transcript.quote_us + packaging_us;
            // Client-side = request prep + network transfer + verify.
            uint64_t network_us = (round_trip_us > server_e2e_us)
                ? (round_trip_us - server_e2e_us) : 0;
            uint64_t client_us = request_prep_us + network_us + verify_us;

            std::cout << spec.id << ","
                      << server_e2e_us << ","
                      << client_us << ","
                      << input_loading_us << ","
                      << transcript.fhe_eval_us << ","
                      << transcript.transcript_us << ","
                      << transcript.quote_us << ","
                      << packaging_us << ","
                      << verify_us << ","
                      << json_peak_mem_kb << ","
                      << transcript_json.size() << ","
                      << quote_bytes.size() << "\n";

        } catch (const std::exception& e) {
            std::cerr << "[benchmark] " << spec.id << ": error: " << e.what()
                      << std::endl;
            all_ok = false;
        }
    }

    std::cerr << "[benchmark] all workloads "
              << (all_ok ? "completed successfully" : "had errors") << std::endl;
    return all_ok ? 0 : 1;
}
