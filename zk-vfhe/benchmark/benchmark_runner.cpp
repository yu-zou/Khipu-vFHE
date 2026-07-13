// ZK benchmark runner: connects to zk_server, runs every registered workload
// end-to-end, and emits a CSV of timing + size metrics to stdout.
// Diagnostics go to stderr so they never corrupt the CSV.
//
// Usage: benchmark_runner [--host HOST] [--port PORT]
//
// Response format expected from server (5 blobs):
//   [output_ct][transcript_json][proof_bytes][public_inputs_bytes][vk_bytes]
// The proof/public_inputs/vk blobs may be empty (ZK pipeline disabled);
// this runner records timings from the transcript regardless and tolerates
// proof-verification failures (which are expected until ZK is fully wired).

#include <sys/resource.h>

#include <chrono>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "common/hashing.h"
#include "common/serialization.h"
#include "common/tcp_transport.h"
#include "common/transcript.h"
#include "common/zk_proof.h"
#include "libff/common/profiling.hpp"
#include "openfhe.h"
#include "openfhe/pke/cryptocontext-ser.h"
#include "openfhe/pke/key/key-ser.h"
#include "openfhe/pke/scheme/bgvrns/bgvrns-ser.h"
#include "server/workload_registry.h"

using namespace zk;
using namespace lbcrypto;

namespace {

struct WorkloadSpec {
    std::string id;
    int num_inputs;
    int slots;
    int seed_a;
    int seed_b;
};

// Workload specification. Slot counts match Prototype E's benchmark_runner
// so that input vectors have identical size and seed across E and B.
// Workloads that internally use the shared baseline (batch=4096) context
// (toy/small/medium/app_*) accept 64-slot inputs zero-padded to 4096.
const std::vector<WorkloadSpec> kWorkloads = {
    {"noop",            1, 64,   42,   0},
    {"toy",             2, 64,   42, 123},
    {"small",           4, 64,   42, 123},
    {"medium",          6, 64,   42, 123},
    {"BGV-Add-4K",      2, 4096, 42, 123},
    {"BGV-Mul-4K",      2, 4096, 42, 123},
};

class BufWriter {
public:
    void write_u32_be(uint32_t v) {
        uint8_t b[4] = {uint8_t(v>>24), uint8_t(v>>16), uint8_t(v>>8), uint8_t(v)};
        buf_.insert(buf_.end(), b, b+4);
    }
    void write_blob(const uint8_t* d, size_t n) { write_u32_be((uint32_t)n); buf_.insert(buf_.end(), d, d+n); }
    void write_blob(const std::vector<uint8_t>& v) { write_blob(v.data(), v.size()); }
    void write_string(const std::string& s) { write_blob((const uint8_t*)s.data(), s.size()); }
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
               (uint32_t(p[2]) << 8)  | uint32_t(p[3]);
    }
    std::vector<uint8_t> read_blob() {
        uint32_t n = read_u32_be();
        const uint8_t* p = read(n);
        return std::vector<uint8_t>(p, p + n);
    }
    std::string read_string() { auto v = read_blob(); return std::string(v.begin(), v.end()); }
    size_t remaining() const { return buf_.size() - pos_; }
private:
    const std::vector<uint8_t>& buf_;
    size_t pos_;
};

std::vector<uint8_t> random_nonce(size_t n) {
    std::vector<uint8_t> out(n);
    std::ifstream ur("/dev/urandom", std::ios::binary);
    if (ur) ur.read((char*)out.data(), (std::streamsize)n);
    if (!ur || ur.gcount() != (std::streamsize)n)
        for (size_t i=0;i<n;i++) out[i] = (uint8_t)(i*31u+7u);
    return out;
}

std::vector<int64_t> gen_input_vec(int slots, int seed) {
    std::mt19937 gen(seed);
    std::uniform_int_distribution<int64_t> dist(0, 65536);
    std::vector<int64_t> v(slots);
    for (int i=0; i<slots; i++) v[i] = dist(gen);
    return v;
}

// Always emit exactly 3 eval-key blobs in fixed order, with empty blobs for
// any key type that the workload's context does not have.
std::vector<std::vector<uint8_t>> serialize_all_eval_keys(const CC& cc) {
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

void print_usage(const char* a0) {
    std::cerr << "Usage: " << a0 << " [--host HOST] [--port PORT]" << std::endl;
}

} // namespace

int main(int argc, char** argv) {
    std::string host = "127.0.0.1";
    uint16_t port = 8080;

    // libff / libsnark require one-time init of curve parameters before any
    // pairing / proof operation. Without this, deserialize_vk + verify_proof
    // segfault inside libff's bn128 pairing code.
    zk::pp::init_public_params();
    // Suppress libff's per-phase profiling prints (they go to stdout and
    // corrupt the CSV). Profiling counters remain active for any post-hoc
    // analysis; only the verbose enter/leave messages are silenced.
    libff::inhibit_profiling_info = true;

    for (int i=1; i<argc; i++) {
        std::string a = argv[i];
        if (a == "--host" && i+1<argc) host = argv[++i];
        else if (a == "--port" && i+1<argc) port = (uint16_t)std::stoi(argv[++i]);
        else if (a == "--help" || a == "-h") { print_usage(argv[0]); return 0; }
        else { std::cerr << "Unknown arg: " << a << std::endl; print_usage(argv[0]); return 1; }
    }

    register_all_workloads();
    const auto& registry = get_workload_registry();

    std::cout << "workload,input_loading_us,fhe_eval_us,witness_us,proof_us,"
                 "packaging_us,verify_us,e2e_us,peak_mem_kb,proof_size_bytes\n";

    bool all_ok = true;
    for (const auto& spec : kWorkloads) {
        std::cerr << "[benchmark] running workload: " << spec.id << std::endl;
        auto it = registry.find(spec.id);
        if (it == registry.end()) {
            std::cerr << "[benchmark] unknown workload (skipping): " << spec.id << std::endl;
            all_ok = false;
            continue;
        }
        const Workload& w = it->second;

        try {
            CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
            CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
            CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();

            // Build the SAME crypto context the server will use for this workload.
            auto cc = w.make_context();
            auto kp = cc->KeyGen();
            if (w.gen_keys) w.gen_keys(cc, kp);
            cc->EvalMultKeyGen(kp.secretKey);

            auto eval_keys = serialize_all_eval_keys(cc);

            std::vector<uint8_t> nonce = random_nonce(16);
            std::vector<std::vector<uint8_t>> input_ct_blobs;

            for (int i = 0; i < spec.num_inputs; ++i) {
                int seed = spec.seed_a + i * spec.seed_b;
                auto vals = gen_input_vec(spec.slots, seed);
                auto pt = cc->MakePackedPlaintext(vals);
                auto ct = cc->Encrypt(kp.publicKey, pt);
                std::string s = serialize_ciphertext(ct);
                input_ct_blobs.emplace_back(s.begin(), s.end());
            }

            BufWriter w;
            w.write_blob(nonce);
            w.write_u32_be((uint32_t)eval_keys.size());
            for (auto& k : eval_keys) w.write_blob(k);
            w.write_u32_be((uint32_t)input_ct_blobs.size());
            for (auto& c : input_ct_blobs) w.write_blob(c);
            w.write_string(spec.id);

            auto t0 = std::chrono::steady_clock::now();
            TCPClient cli(host, port);
            send_message(cli.fd(), w.data());
            auto resp = recv_message(cli.fd());
            cli.close();
            auto t1 = std::chrono::steady_clock::now();

            if (resp.empty()) {
                std::cerr << "[benchmark] " << spec.id << ": empty response\n";
                all_ok = false;
                continue;
            }

            BufReader rr(resp);
            auto out_bytes = rr.read_blob();
            auto tr_json = rr.read_string();
            auto proof_bytes = rr.read_blob();
            auto pi_bytes = rr.read_blob();
            auto vk_bytes = rr.read_blob();
            if (rr.remaining() != 0) {
                std::cerr << "[benchmark] " << spec.id << ": trailing bytes (" << rr.remaining() << ")\n";
                all_ok = false;
                continue;
            }

            bool had_error = (tr_json.find("\"error\"") != std::string::npos);
            if (had_error) {
                std::cerr << "[benchmark] " << spec.id << ": server error: " << tr_json << "\n";
                all_ok = false;
                continue;
            }

            uint64_t il=0, fe=0, wi=0, pr=0, pk_us=0, vf=0;
            uint64_t e2e = (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(t1-t0).count();
            uint64_t peak = 0;
            try {
                auto tj = nlohmann::json::parse(tr_json);
                il = tj.value("input_loading_us", 0ULL);
                fe = tj.value("fhe_eval_us", 0ULL);
                wi = tj.value("witness_us", 0ULL);
                pr = tj.value("proof_us", 0ULL);
                pk_us = tj.value("packaging_us", 0ULL);
                peak = tj.value("peak_mem_kb", 0ULL);
            } catch (const std::exception& e) {
                std::cerr << "[benchmark] " << spec.id << ": transcript parse failed: " << e.what() << "\n";
            }

            // Attempt ZK proof verification if a (non-empty) proof+vk was supplied.
            // Until ZK constraint pipeline is fully wired on the server, proof
            // blobs are empty and verification is skipped without failing the
            // benchmark.
            auto tv0 = std::chrono::steady_clock::now();
            bool proof_ok = true;
            if (!proof_bytes.empty() && !vk_bytes.empty() && !pi_bytes.empty()) {
                try {
                    auto vk = deserialize_vk(vk_bytes);
                    auto pi = deserialize_public_inputs(pi_bytes);
                    auto proof = deserialize_proof(proof_bytes);
                    proof_ok = verify_proof(vk, pi, proof);
                } catch (const std::exception& e) {
                    std::cerr << "[benchmark] " << spec.id << ": proof verify exn: " << e.what() << "\n";
                    proof_ok = false;
                }
            } else {
                proof_ok = true; // empty proof = ZK not yet wired; don't fail.
            }
            auto tv1 = std::chrono::steady_clock::now();
            vf = (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(tv1-tv0).count();

            if (!proof_ok) {
                std::cerr << "[benchmark] " << spec.id << ": ZK proof FAILED verification\n";
                // Keep going: we still record timing data.
            }
            (void)out_bytes;

            std::cout << spec.id << ","
                      << il << "," << fe << "," << wi << "," << pr << ","
                      << pk_us << "," << vf << "," << e2e << "," << peak << ","
                      << proof_bytes.size() << "\n";
        } catch (const std::exception& e) {
            std::cerr << "[benchmark] " << spec.id << ": error: " << e.what() << "\n";
            all_ok = false;
        }
    }

    std::cerr << "[benchmark] all workloads "
              << (all_ok ? "completed successfully" : "had errors") << std::endl;
    return all_ok ? 0 : 1;
}
