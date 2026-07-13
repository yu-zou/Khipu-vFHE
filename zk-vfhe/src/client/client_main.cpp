// zk_client: connects to zk_server, encrypts inputs under BGV, sends the
// REQUEST, receives the RESPONSE, optionally verifies the ZK proof, and
// decrypts the output.
//
// Current state: the server's three-pass ZK constraint/witness/proof pipeline
// is not fully wired (it returns empty proof/public-input/VK blobs); this
// client accepts empty proof blobs (treating them as "ZK not yet available")
// and decrypts the output ciphertext regardless so that functional testing
// of the FHE pipeline can proceed.

#include <arpa/inet.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "client/verifier.h"
#include "common/hashing.h"
#include "common/serialization.h"
#include "common/tcp_transport.h"
#include "common/transcript.h"
#include "openfhe.h"
#include "openfhe/pke/cryptocontext-ser.h"
#include "openfhe/pke/key/key-ser.h"
#include "openfhe/pke/scheme/bgvrns/bgvrns-ser.h"
#include "server/workload_registry.h"

using namespace lbcrypto;
using namespace zk;

// ── Wire-format helpers ────────────────────────────────────────────────────────

class BufReader {
public:
    explicit BufReader(const std::vector<uint8_t>& buf) : buf_(buf), pos_(0) {}
    const uint8_t* read(size_t n) {
        if (pos_ + n > buf_.size()) throw std::runtime_error("truncated");
        const uint8_t* p = buf_.data() + pos_; pos_ += n; return p;
    }
    uint32_t read_u32_be() {
        const uint8_t* p = read(4);
        return (uint32_t(p[0])<<24)|(uint32_t(p[1])<<16)|(uint32_t(p[2])<<8)|uint32_t(p[3]);
    }
    std::vector<uint8_t> read_blob() { uint32_t n = read_u32_be(); const uint8_t* p = read(n); return {p, p+n}; }
    std::string read_string() { auto v = read_blob(); return std::string(v.begin(), v.end()); }
    size_t remaining() const { return buf_.size() - pos_; }
private:
    const std::vector<uint8_t>& buf_;
    size_t pos_;
};

class BufWriter {
public:
    void write_u32_be(uint32_t v) {
        uint8_t b[4] = { uint8_t(v>>24), uint8_t(v>>16), uint8_t(v>>8), uint8_t(v) };
        buf_.insert(buf_.end(), b, b+4);
    }
    void write_blob(const uint8_t* d, size_t n) { write_u32_be((uint32_t)n); buf_.insert(buf_.end(), d, d+n); }
    void write_blob(const std::vector<uint8_t>& v) { write_blob(v.data(), v.size()); }
    void write_string(const std::string& s) { write_blob((const uint8_t*)s.data(), s.size()); }
    const std::vector<uint8_t>& data() const { return buf_; }
private:
    std::vector<uint8_t> buf_;
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
    for (int i=0;i<slots;i++) v[i] = dist(gen);
    return v;
}

std::vector<std::vector<uint8_t>> serialize_all_eval_keys(const CC& cc) {
    std::vector<std::vector<uint8_t>> blobs(3);
    {
        std::ostringstream oss(std::ios::binary);
        if (CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey(oss, SerType::BINARY, cc)) {
            std::string s = oss.str(); blobs[0].assign(s.begin(), s.end());
        }
    }
    {
        std::ostringstream oss(std::ios::binary);
        if (CryptoContextImpl<DCRTPoly>::SerializeEvalSumKey(oss, SerType::BINARY, cc)) {
            std::string s = oss.str(); blobs[1].assign(s.begin(), s.end());
        }
    }
    {
        std::ostringstream oss(std::ios::binary);
        if (CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey(oss, SerType::BINARY, cc)) {
            std::string s = oss.str(); blobs[2].assign(s.begin(), s.end());
        }
    }
    return blobs;
}

void print_usage(const char* a0) {
    std::cerr << "Usage: " << a0
              << " [--host HOST] [--port PORT] [--workload ID]"
                 " [--inputs N] [--slots N] [--seed N] [--help|-h]\n";
}

int main(int argc, char** argv) {
    std::string host = "127.0.0.1";
    uint16_t port = 8080;
    std::string workload_id = "toy";
    int num_inputs = 2;
    int slots = 64;
    int seed_a = 42;
    int seed_b = 123;

    for (int i=1; i<argc; i++) {
        std::string a = argv[i];
        if (a == "--host" && i+1<argc) host = argv[++i];
        else if (a == "--port" && i+1<argc) port = (uint16_t)std::stoi(argv[++i]);
        else if (a == "--workload" && i+1<argc) workload_id = argv[++i];
        else if (a == "--inputs" && i+1<argc) num_inputs = std::stoi(argv[++i]);
        else if (a == "--slots" && i+1<argc) slots = std::stoi(argv[++i]);
        else if (a == "--seed" && i+1<argc) seed_a = std::stoi(argv[++i]);
        else if (a == "--help" || a == "-h") { print_usage(argv[0]); return 0; }
        else { std::cerr << "Unknown arg: " << a << "\n"; print_usage(argv[0]); return 1; }
    }

    // Workload dispatch: override defaults based on workload_id
    struct WorkloadDefaults {
        const char* id;
        int num_inputs;
        int slots;
    };
    static const WorkloadDefaults kWorkloadDefaults[] = {
        {"noop",         1, 64},
        {"toy",          2, 64},
        {"small",        4, 64},
        {"medium",       6, 64},
        {"BGV-Add-4K",   2, 4096},
        {"BGV-Mul-4K",   2, 4096},
    };
    for (const auto& wd : kWorkloadDefaults) {
        if (workload_id == wd.id) {
            num_inputs = wd.num_inputs;
            slots = wd.slots;
            break;
        }
    }

    try {
        register_all_workloads();
        auto& registry = get_workload_registry();
        auto it = registry.find(workload_id);
        if (it == registry.end()) {
            std::cerr << "[client] unknown workload: " << workload_id << "\n";
            return 1;
        }
        const Workload& wl = it->second;

        CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
        CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
        CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();

        auto cc = wl.make_context();
        auto kp = cc->KeyGen();
        if (wl.gen_keys) wl.gen_keys(cc, kp);
        cc->EvalMultKeyGen(kp.secretKey);

        std::cout << "[client] BGV keys generated (workload=" << workload_id
                  << ", slots=" << slots << ", p=65537)\n";

        std::vector<uint8_t> nonce = random_nonce(16);
        auto eval_keys = serialize_all_eval_keys(cc);

        std::vector<std::vector<uint8_t>> input_ct_blobs;
        std::vector<Ciphertext<DCRTPoly>> input_cts;
        for (int i = 0; i < num_inputs; ++i) {
            int seed = seed_a + i * seed_b;
            auto v = gen_input_vec(slots, seed);
            auto pt = cc->MakePackedPlaintext(v);
            auto ct = cc->Encrypt(kp.publicKey, pt);
            input_cts.push_back(ct);
            std::string s = serialize_ciphertext(ct);
            input_ct_blobs.emplace_back(s.begin(), s.end());
        }
        std::cout << "[client] encrypted " << num_inputs << " input ciphertext(s)\n";

        BufWriter w;
        w.write_blob(nonce);
        w.write_u32_be((uint32_t)eval_keys.size());
        for (auto& kb : eval_keys) w.write_blob(kb);
        w.write_u32_be((uint32_t)input_ct_blobs.size());
        for (auto& cb : input_ct_blobs) w.write_blob(cb);
        w.write_string(workload_id);

        std::cout << "[client] connecting to " << host << ":" << port << "...\n";
        TCPClient cli(host, port);
        send_message(cli.fd(), w.data());
        std::cout << "[client] REQUEST sent (" << w.data().size() << " bytes)\n";
        auto resp = recv_message(cli.fd());
        cli.close();
        std::cout << "[client] RESPONSE received (" << resp.size() << " bytes)\n";
        if (resp.empty()) { std::cerr << "[client] empty response\n"; return 1; }

        // 5-blob response: output_ct | transcript_json | proof | public_inputs | vk
        BufReader rr(resp);
        auto out_bytes = rr.read_blob();
        auto tr_json = rr.read_string();
        auto proof_bytes = rr.read_blob();
        auto pi_bytes = rr.read_blob();
        auto vk_bytes = rr.read_blob();
        if (rr.remaining() != 0) {
            std::cerr << "[client] trailing bytes in response: " << rr.remaining() << "\n";
            return 1;
        }

        if (tr_json.find("\"error\"") != std::string::npos) {
            std::cerr << "[client] server error: " << tr_json << "\n";
            return 1;
        }

        bool proof_ok = true;
        if (!proof_bytes.empty() && !vk_bytes.empty() && !pi_bytes.empty()) {
            std::cout << "[client] verifying ZK proof...\n";
            Verifier ver;
            proof_ok = ver.verify_proof(proof_bytes, pi_bytes, vk_bytes);
            if (!proof_ok) {
                std::cerr << "[client] ZK proof VERIFICATION FAILED; refusing to decrypt\n";
                return 1;
            }
            std::cout << "[client] ZK proof verification PASSED\n";
        } else {
            std::cout << "[client] (ZK proof blobs empty - ZK pipeline not yet wired; "
                         "decrypting for functional testing)\n";
        }

        auto out_ct = deserialize_ciphertext(std::string(out_bytes.begin(), out_bytes.end()));
        Plaintext pt_out;
        cc->Decrypt(kp.secretKey, out_ct, &pt_out);
        pt_out->SetLength((size_t)slots);
        auto dec = pt_out->GetPackedValue();

        std::cout << "output[0..7] =";
        for (int i=0; i<8 && i<(int)dec.size(); i++) std::cout << " " << dec[i];
        std::cout << "\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[client] error: " << e.what() << "\n";
        return 1;
    }
}
