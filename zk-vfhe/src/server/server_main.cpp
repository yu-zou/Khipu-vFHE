// zk-vfhe server: ZK-proof-based verifiable FHE server.
//
// Per-request pipeline:
//  1. Plain FHE evaluation to produce the output ciphertext (needed for the
//     transcript's output_ct_hash and for the client's result).
//  2. Three-pass ZK pipeline (constraint → witness → Groth16 proof) using
//     zkOpenFHE's LibsnarkProofSystem wrapper, followed by libsnark proving.
//  3. Serialize output_ct, transcript JSON, proof_bytes, public_inputs_bytes,
//     and verification_key_bytes into a 5-blob response.
//
// Startup: registers workloads, writes per-workload dummy VK files for the
//          client's pre-load check, listens for TCP requests.

#include <arpa/inet.h>
#include <malloc.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/resource.h>
#include <thread>
#include <vector>

#include "openfhe.h"
#include "openfhe/pke/cryptocontext-ser.h"
#include "openfhe/pke/key/key-ser.h"
#include "openfhe/pke/scheme/bgvrns/bgvrns-ser.h"
#include "libff/common/profiling.hpp"
#include "proofsystem/proofsystem_libsnark.h"

#include "common/hashing.h"
#include "common/serialization.h"
#include "common/tcp_transport.h"
#include "common/transcript.h"
#include "common/zk_proof.h"
#include "server/workload_registry.h"

using namespace zk;
using namespace lbcrypto;

namespace {

using CT = Ciphertext<DCRTPoly>;
using CC = CryptoContext<DCRTPoly>;

// BufReader / BufWriter for big-endian length-prefixed framing.
class BufReader {
public:
    explicit BufReader(const std::vector<uint8_t>& buf) : buf_(buf), pos_(0) {}
    const uint8_t* read(size_t n) {
        if (pos_ + n > buf_.size()) throw std::runtime_error("truncated");
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
        uint8_t len_bytes[8];
        std::memcpy(len_bytes, buf_.data() + pos_, 8);
        pos_ += 8;
        uint64_t n = 0;
        for (int i = 0; i < 8; i++) { n = (n << 8) | len_bytes[i]; }
        const uint8_t* p = read(n);
        return std::vector<uint8_t>(p, p + n);
    }
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
    void write_blob(const uint8_t* d, size_t n) {
        uint64_t n64 = n;
        uint8_t len_bytes[8];
        for (int i = 7; i >= 0; i--) { len_bytes[i] = n64 & 0xFF; n64 >>= 8; }
        buf_.insert(buf_.end(), len_bytes, len_bytes + 8);
        buf_.insert(buf_.end(), d, d + n);
    }
    void write_blob(const std::vector<uint8_t>& v) { write_blob(v.data(), v.size()); }
    void write_string(const std::string& s) { write_blob((const uint8_t*)s.data(), s.size()); }
    const std::vector<uint8_t>& data() const { return buf_; }
private:
    std::vector<uint8_t> buf_;
};

Transcript build_transcript(const std::vector<uint8_t>& nonce,
                            const std::vector<std::vector<uint8_t>>& eval_key_blobs,
                            const std::vector<std::vector<uint8_t>>& input_ct_blobs,
                            const std::vector<uint8_t>& output_ct_bytes) {
    Transcript t;
    t.nonce = nonce;
    Hash32 ekh{};
    if (!eval_key_blobs.empty()) {
        std::vector<uint8_t> c;
        for (auto& kb : eval_key_blobs) c.insert(c.end(), kb.begin(), kb.end());
        ekh = blake3_hash(c);
    }
    t.eval_key_hash = ekh;
    t.input_ct_hashes.reserve(input_ct_blobs.size());
    for (auto& cb : input_ct_blobs) t.input_ct_hashes.push_back(blake3_hash(cb));
    t.output_ct_hash = blake3_hash(output_ct_bytes);
    return t;
}

std::vector<uint8_t> build_error_response(const std::string& msg) {
    BufWriter w;
    std::vector<uint8_t> empty;
    w.write_blob(empty);
    w.write_string(std::string("{\"error\":\"") + msg + "\"}");
    w.write_blob(empty);
    w.write_blob(empty);
    w.write_blob(empty);
    return w.data();
}

// Client sends keys in fixed order: [0]=EvalMultKey, [1]=EvalSumKey, [2]=EvalAutomorphismKey.
void deserialize_eval_key_by_index(size_t idx, const std::vector<uint8_t>& kb) {
    if (kb.empty()) return;
    std::string s(kb.begin(), kb.end());
    std::istringstream iss(s, std::ios::binary);
    bool ok = false;
    if (idx == 0) ok = CryptoContextImpl<DCRTPoly>::DeserializeEvalMultKey(iss, SerType::BINARY);
    else if (idx == 1) ok = CryptoContextImpl<DCRTPoly>::DeserializeEvalSumKey(iss, SerType::BINARY);
    else ok = CryptoContextImpl<DCRTPoly>::DeserializeEvalAutomorphismKey(iss, SerType::BINARY);
    if (!ok) throw std::runtime_error("eval key[" + std::to_string(idx) + "] deserialization returned false");
}

void write_dummy_vk_file(const std::string& wid) {
    std::string fn = "/tmp/zk-vfhe-vk-" + wid + ".bin";
    std::ofstream ofs(fn, std::ios::binary);
    if (!ofs) { std::cerr << "[server] cannot write VK file " << fn << std::endl; return; }
    const char m[] = "ZK_PROOF_PLACEHOLDER";
    ofs.write(m, sizeof(m)-1);
}

void handle_client(int client_fd) {
    using clock = std::chrono::steady_clock;
    using us = std::chrono::microseconds;

    std::vector<uint8_t> req;
    try { req = recv_message(client_fd); }
    catch (const std::exception& e) { std::cerr << "[server] recv: " << e.what() << std::endl; return; }

    std::vector<uint8_t> nonce;
    std::vector<std::vector<uint8_t>> eval_key_blobs, input_ct_blobs;
    std::string workload_id;
    try {
        BufReader r(req);
        nonce = r.read_blob();
        uint32_t nk = r.read_u32_be();
        eval_key_blobs.reserve(nk);
        for (uint32_t i=0; i<nk; i++) eval_key_blobs.push_back(r.read_blob());
        uint32_t nc = r.read_u32_be();
        input_ct_blobs.reserve(nc);
        for (uint32_t i=0; i<nc; i++) input_ct_blobs.push_back(r.read_blob());
        workload_id = r.read_string();
        if (r.remaining() != 0) throw std::runtime_error("trailing bytes");
    } catch (const std::exception& e) {
        std::cerr << "[server] bad request: " << e.what() << std::endl;
        try { send_message(client_fd, build_error_response(std::string("bad request: ")+e.what())); } catch(...) {}
        return;
    }

    auto& registry = get_workload_registry();
    auto it = registry.find(workload_id);
    if (it == registry.end()) {
        std::cerr << "[server] unknown workload: " << workload_id << std::endl;
        try { send_message(client_fd, build_error_response("unknown workload: "+workload_id)); } catch(...) {}
        return;
    }
    const Workload& w = it->second;

    CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
    CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
    CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();

    auto t_cc0 = clock::now();
    // Build the server-side CryptoContext with IDENTICAL parameters to what
    // the client used. OpenFHE's CryptoContextFactory deduplicates contexts
    // by parameter set so deserialized ciphertexts (which embed a partial cc)
    // resolve back to this cc via GetFullContextByDeserializedContext().
    // The client sends all required eval keys (EvalMult/EvalSum/Automorphism)
    // in the request; we deserialize those below instead of regenerating keys
    // on the server (which would create a different key pair and mismatch).
    CC cc = w.make_context();
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    auto t_cc1 = clock::now();

    auto t_load0 = clock::now();
    try {
        for (size_t i=0; i<eval_key_blobs.size(); i++) deserialize_eval_key_by_index(i, eval_key_blobs[i]);
    } catch (const std::exception& e) {
        std::cerr << "[server] key load failed: " << e.what() << std::endl;
        try { send_message(client_fd, build_error_response(std::string("bad key: ")+e.what())); } catch(...) {}
        return;
    }
    std::vector<CT> inputs;
    inputs.reserve(input_ct_blobs.size());
    try {
        for (auto& cb : input_ct_blobs) {
            std::string s(cb.begin(), cb.end());
            inputs.push_back(deserialize_ciphertext(s));
        }
    } catch (const std::exception& e) {
        std::cerr << "[server] ct load failed: " << e.what() << std::endl;
        try { send_message(client_fd, build_error_response(std::string("bad ct: ")+e.what())); } catch(...) {}
        return;
    }
    auto t_load1 = clock::now();

    auto t_eval0 = clock::now();
    CT out;
    try { out = w.eval(cc, inputs); }
    catch (const std::exception& e) {
        std::cerr << "[server] eval failed: " << e.what() << std::endl;
        try { send_message(client_fd, build_error_response(std::string("eval failed: ")+e.what())); } catch(...) {}
        return;
    }
    auto t_eval1 = clock::now();

    // ── Three-pass ZK proof generation (constraint → witness → proof) ──────
    std::vector<uint8_t> proof_bytes, pi_bytes, vk_bytes;
    uint64_t witness_us = 0, proof_us = 0;

    if (w.eval_zk) {
        auto log_phase = [](const char* phase, clock::time_point t0) {
            std::cerr << "[server]   zk-phase=" << phase << "  "
                      << std::chrono::duration_cast<std::chrono::milliseconds>(clock::now() - t0).count()
                      << "ms" << std::endl;
        };
        try {
            std::cerr << "[server] zk start workload=" << workload_id << std::endl;

            std::vector<CT> zk_inputs;
            zk_inputs.reserve(input_ct_blobs.size());
            for (auto& cb : input_ct_blobs) {
                std::string s(cb.begin(), cb.end());
                zk_inputs.push_back(deserialize_ciphertext(s));
            }

            // Pass 1: constraint generation (builds R1CS, no actual computation).
            auto t_p1 = clock::now();
            LibsnarkProofSystem ps(cc);
            ps.SetMode(PROOFSYSTEM_MODE_CONSTRAINT_GENERATION);
            std::cerr << "[server]   zk pass1 mode=set constraint_gen" << std::endl;
            {
                CT zk_out_c = w.eval_zk(ps, zk_inputs);
                (void)zk_out_c;
            }
            log_phase("pass1_constraint_gen", t_p1);

            // Pass 2: witness generation.
            zk_inputs.clear();
            for (auto& cb : input_ct_blobs) {
                std::string s(cb.begin(), cb.end());
                zk_inputs.push_back(deserialize_ciphertext(s));
            }
            auto t_p2 = clock::now();
            ps.SetMode(PROOFSYSTEM_MODE_WITNESS_GENERATION);
            std::cerr << "[server]   zk pass2 mode=set witness_gen" << std::endl;
            {
                CT zk_out_w = w.eval_zk(ps, zk_inputs);
                (void)zk_out_w;
            }
            log_phase("pass2_witness_gen", t_p2);

            auto t_witness_end = clock::now();
            witness_us = (uint64_t)std::chrono::duration_cast<us>(t_witness_end - t_eval1).count();

            // Extract constraint system and witness values.
            auto t_extract = clock::now();
            auto cs = ps.pb.get_constraint_system();
            auto primary_input = ps.pb.primary_input();
            auto auxiliary_input = ps.pb.auxiliary_input();
            std::cerr << "[server]   zk extract  constraints=" << cs.num_constraints()
                      << "  primary=" << primary_input.size()
                      << "  aux=" << auxiliary_input.size() << std::endl;
            log_phase("extract_cs", t_extract);

            if (cs.num_constraints() == 0) {
                // EvalAdd-only workloads produce no R1CS constraints (addition
                // is linear, captured in the witness not as A*B=C constraints).
                // Skip the ZK pipeline gracefully - there is nothing to prove.
                std::cerr << "[server]   zk skip: constraint system is empty "
                          << "(linear workload, no multiplication to prove)"
                          << std::endl;
            } else {
                if (!cs.is_satisfied(primary_input, auxiliary_input)) {
                    throw std::runtime_error("constraint system not satisfied by witness");
                }
                std::cerr << "[server]   zk cs satisfied" << std::endl;

                // Pass 3: key setup + Groth16/PGHR13 proof generation.
                auto t_setup = clock::now();
                auto zk_vk = zk::setup(cs);
                log_phase("pass3a_setup", t_setup);

                auto t_proof_start = clock::now();
                auto zk_proof = zk::prove(primary_input, auxiliary_input);
                auto t_proof_end = clock::now();
                log_phase("pass3b_prove", t_proof_start);
                proof_us = (uint64_t)std::chrono::duration_cast<us>(t_proof_end - t_proof_start).count();

                // Serialize proof artifacts.
                proof_bytes = zk::serialize_proof(zk_proof);
                pi_bytes = zk::serialize_public_inputs(primary_input);
                vk_bytes = zk::serialize_vk(zk_vk);

                std::cerr << "[server] ZK ok: constraints=" << cs.num_constraints()
                          << "  primary_inputs=" << primary_input.size()
                          << "  aux_inputs=" << auxiliary_input.size()
                          << "  proof_bytes=" << proof_bytes.size()
                          << "  vk_bytes=" << vk_bytes.size() << std::endl;

                // Release the cached proving key (can be hundreds of MB for large
                // constraint systems) so subsequent workloads don't trigger OOM.
                zk::clear_cached_keypair();
                // Return freed heap to the OS. Without this, glibc retains the
                // freed pages in its arena and the next r1cs_ppzksnark_generator
                // call (which allocates a fresh, larger key) pushes us over the
                // system memory limit.
                malloc_trim(0);
            }
        } catch (const std::exception& e) {
            std::cerr << "[server] ZK proof generation FAILED for workload=" << workload_id
                      << ": " << e.what() << std::endl
                      << "[server]   (proof blobs will be empty; witness_us/proof_us zeroed)"
                      << std::endl;
            proof_bytes.clear();
            pi_bytes.clear();
            vk_bytes.clear();
            witness_us = 0;
            proof_us = 0;
        }
    }

    std::string out_str;
    try { out_str = serialize_ciphertext(out); }
    catch (const std::exception& e) {
        std::cerr << "[server] serialize failed: " << e.what() << std::endl;
        try { send_message(client_fd, build_error_response(std::string("serialize: ")+e.what())); } catch(...) {}
        return;
    }
    std::vector<uint8_t> out_bytes(out_str.begin(), out_str.end());

    auto t_tr0 = clock::now();
    Transcript tr = build_transcript(nonce, eval_key_blobs, input_ct_blobs, out_bytes);
    tr.fhe_eval_us       = (uint64_t)std::chrono::duration_cast<us>(t_eval1-t_eval0).count();
    tr.witness_us        = witness_us;
    tr.proof_us          = proof_us;
    tr.input_loading_us  = (uint64_t)std::chrono::duration_cast<us>(t_load1-t_load0).count();
    tr.peak_mem_kb       = 0;
    auto t_tr1 = clock::now();
    tr.transcript_us     = (uint64_t)std::chrono::duration_cast<us>(t_tr1-t_tr0).count();
    struct rusage ru; getrusage(RUSAGE_SELF, &ru);
    tr.peak_mem_kb = (uint64_t)ru.ru_maxrss;

    std::string tr_json = tr.to_json();

    BufWriter bw;
    bw.write_blob(out_bytes);
    bw.write_string(tr_json);
    bw.write_blob(proof_bytes);
    bw.write_blob(pi_bytes);
    bw.write_blob(vk_bytes);

    try { send_message(client_fd, bw.data()); }
    catch (const std::exception& e) { std::cerr << "[server] send failed: " << e.what() << std::endl; }
    auto t_pack1 = clock::now();

    using ms = std::chrono::milliseconds;
    std::cerr << "[server] workload=" << workload_id
              << "  ctx=" << std::chrono::duration_cast<ms>(t_cc1-t_cc0).count()<<"ms"
              << "  load=" << std::chrono::duration_cast<ms>(t_load1-t_load0).count()<<"ms"
              << "  eval=" << std::chrono::duration_cast<ms>(t_eval1-t_eval0).count()<<"ms"
              << "  witness=" << std::chrono::duration_cast<ms>(
                    std::chrono::microseconds(witness_us)).count()<<"ms"
              << "  proof=" << std::chrono::duration_cast<ms>(
                    std::chrono::microseconds(proof_us)).count()<<"ms"
              << "  mem_kb=" << tr.peak_mem_kb << std::endl;
    (void)t_pack1;
}

void print_usage(const char* a0) {
    std::cerr << "Usage: " << a0 << " [--port PORT]" << std::endl;
}

} // namespace

int main(int argc, char** argv) {
    uint16_t port = 8080;
    for (int i=1; i<argc; i++) {
        std::string a = argv[i];
        if (a == "--port" && i+1<argc) port = (uint16_t)std::stoi(argv[++i]);
        else if (a == "--help" || a == "-h") { print_usage(argv[0]); return 0; }
        else { std::cerr << "Unknown arg: " << a << std::endl; print_usage(argv[0]); return 1; }
    }

    register_all_workloads();
    auto& registry = get_workload_registry();
    std::cerr << "[server] registered " << registry.size() << " workloads" << std::endl;
    for (auto& [wid, _w] : registry) write_dummy_vk_file(wid);

    // Suppress libff's verbose profiling prints (enter/leave for every pairing
    // call). They go to stdout and would corrupt the benchmark CSV if the
    // server's stdout were redirected there. Profiling counters stay active.
    libff::inhibit_profiling_info = true;

    std::cerr << "[server] listening on 0.0.0.0:" << port << std::endl;
    TCPServer srv("0.0.0.0", port);
    std::cerr << "[server] bound to port " << srv.port() << std::endl;

    try {
        for (;;) {
            Socket c;
            try { c = srv.accept(); }
            catch (const std::exception& e) { std::cerr << "[server] accept: " << e.what() << std::endl; break; }
            int fd = c.release();
            std::thread([fd](){
                try { handle_client(fd); }
                catch (const std::exception& e) { std::cerr << "[server] handler exn: " << e.what() << std::endl; }
                catch (...) { std::cerr << "[server] handler unknown exn" << std::endl; }
                ::close(fd);
            }).detach();
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[server] fatal: " << e.what() << std::endl;
        return 1;
    }
}
