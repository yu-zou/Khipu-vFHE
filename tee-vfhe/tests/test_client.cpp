#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include "client/verifier.h"
#include "common/attestation.h"
#include "common/hashing.h"
#include "common/serialization.h"
#include "common/tcp_transport.h"
#include "openfhe.h"
#include "openfhe/pke/cryptocontext-ser.h"
#include "openfhe/pke/key/key-ser.h"
#include "openfhe/pke/scheme/ckksrns/ckksrns-ser.h"
#include "server/workload_registry.h"

using namespace tee;
using namespace lbcrypto;

namespace {

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
               (uint32_t(p[2]) << 8) | uint32_t(p[3]);
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

void run_dispatch_one(TCPServer& srv, std::atomic<bool>& stop) {
    while (!stop.load()) {
        Socket client;
        try {
            client = srv.accept();
        } catch (const std::exception&) {
            return;
        }
        int fd = client.release();
        std::thread([fd]() {
            try {
                auto req = recv_message(fd);
                BufReader r(req);
                auto nonce = r.read_blob();
                uint32_t num_keys = r.read_u32_be();
                std::vector<std::vector<uint8_t>> eval_keys;
                eval_keys.reserve(num_keys);
                for (uint32_t i = 0; i < num_keys; ++i) eval_keys.push_back(r.read_blob());
                uint32_t num_cts = r.read_u32_be();
                std::vector<std::vector<uint8_t>> input_cts;
                input_cts.reserve(num_cts);
                for (uint32_t i = 0; i < num_cts; ++i) input_cts.push_back(r.read_blob());
                auto wid = r.read_string();

                auto& reg = get_workload_registry();
                auto it = reg.find(wid);
                if (it == reg.end()) {
                    BufWriter ew;
                    std::vector<uint8_t> empty;
                    ew.write_blob(empty);
                    ew.write_string(std::string("{\"error\":\"unknown workload: ") + wid + "\"}");
                    ew.write_blob(empty);
                    send_message(fd, ew.data());
                    ::close(fd);
                    return;
                }
                const Workload& w = it->second;
                auto cc = w.make_context();

                // In-process tests share OpenFHE's global key container with the
                // client; clear any lingering keys before deserializing the ones
                // sent over the wire (production client/server are separate processes).
                cc->ClearEvalMultKeys();
                for (auto& kb : eval_keys) {
                    std::string s(kb.begin(), kb.end());
                    std::istringstream iss(s, std::ios::binary);
                    try {
                        CryptoContextImpl<DCRTPoly>::DeserializeEvalMultKey(iss, SerType::BINARY);
                    } catch (const std::exception& e) {
                        std::cerr << "[test-srv] DeserializeEvalMultKey failed: " << e.what() << std::endl;
                        BufWriter ew;
                        std::vector<uint8_t> empty;
                        ew.write_blob(empty);
                        ew.write_string(std::string("{\"error\":\"bad eval key: ") + e.what() + "\"}");
                        ew.write_blob(empty);
                        send_message(fd, ew.data());
                        ::close(fd);
                        return;
                    }
                }

                std::vector<Ciphertext<DCRTPoly>> inputs;
                inputs.reserve(input_cts.size());
                for (auto& cb : input_cts) {
                    std::string s(cb.begin(), cb.end());
                    inputs.push_back(deserialize_ciphertext(s));
                }

                auto out_ct = w.eval(cc, inputs);
                std::string out_str = serialize_ciphertext(out_ct);
                std::vector<uint8_t> out_bytes(out_str.begin(), out_str.end());

                auto transcript = generate_transcript(nonce, eval_keys, input_cts, out_bytes);
                std::string tjson = transcript.to_json();
                auto hash = compute_transcript_hash(transcript);
                std::vector<uint8_t> quote;
                try {
                    quote = generate_tdx_quote(hash);
                } catch (const std::exception&) {
                    quote.clear();
                }

                BufWriter rw;
                rw.write_blob(out_bytes);
                rw.write_string(tjson);
                rw.write_blob(quote);
                send_message(fd, rw.data());
            } catch (const std::exception&) {
                // client closed or protocol error
            }
            ::close(fd);
        }).detach();
    }
}

std::vector<uint8_t> random_nonce(size_t n) {
    std::vector<uint8_t> out(n);
    std::ifstream ur("/dev/urandom", std::ios::binary);
    if (ur) {
        ur.read(reinterpret_cast<char*>(out.data()),
                static_cast<std::streamsize>(n));
    }
    if (!ur || ur.gcount() != static_cast<std::streamsize>(n)) {
        for (size_t i = 0; i < n; ++i) out[i] = (uint8_t)(i * 31u + 7u);
    }
    return out;
}

Hash32 hash_concatenated(const std::vector<std::vector<uint8_t>>& parts) {
    std::vector<uint8_t> buf;
    size_t total = 0;
    for (auto& p : parts) total += p.size();
    buf.reserve(total);
    for (auto& p : parts) buf.insert(buf.end(), p.begin(), p.end());
    return blake3_hash(buf);
}

}  // namespace

TEST(ClientLogic, BuildRequestParseResponseDecrypt) {
    TCPServer srv("127.0.0.1", 0);
    uint16_t port = srv.port();
    ASSERT_NE(port, 0);

    std::atomic<bool> stop{false};
    std::thread srv_thread(run_dispatch_one, std::ref(srv), std::ref(stop));

    auto& registry = get_workload_registry();
    auto it = registry.find("noop");
    ASSERT_TRUE(it != registry.end());
    const Workload& workload = it->second;
    auto cc = workload.make_context();
    auto kp = cc->KeyGen();
    cc->EvalMultKeyGen(kp.secretKey);

    std::ostringstream emk_oss(std::ios::binary);
    CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey(emk_oss, SerType::BINARY);
    std::string emk_s = emk_oss.str();
    std::vector<std::vector<uint8_t>> eval_keys;
    eval_keys.emplace_back(emk_s.begin(), emk_s.end());

    std::vector<double> vals(32, 1.0);
    auto pt = cc->MakeCKKSPackedPlaintext(vals);
    auto ct = cc->Encrypt(kp.publicKey, pt);
    std::string ct_s = serialize_ciphertext(ct);
    std::vector<std::vector<uint8_t>> input_ct_blobs;
    input_ct_blobs.emplace_back(ct_s.begin(), ct_s.end());

    auto nonce = random_nonce(16);

    BufWriter w;
    w.write_blob(nonce);
    w.write_u32_be((uint32_t)eval_keys.size());
    for (auto& k : eval_keys) w.write_blob(k);
    w.write_u32_be((uint32_t)input_ct_blobs.size());
    for (auto& c : input_ct_blobs) w.write_blob(c);
    w.write_string("noop");

    std::vector<uint8_t> resp;
    try {
        TCPClient cli("127.0.0.1", port);
        send_message(cli.fd(), w.data());
        resp = recv_message(cli.fd());
        cli.close();
    } catch (...) {
        stop.store(true);
        srv.close();
        try { TCPClient("127.0.0.1", port).close(); } catch (...) {}
        srv_thread.join();
        throw;
    }

    stop.store(true);
    srv.close();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    try { TCPClient("127.0.0.1", port).close(); } catch (...) {}
    srv_thread.join();

    ASSERT_FALSE(resp.empty());
    BufReader rr(resp);
    auto out_bytes = rr.read_blob();
    auto tjson = rr.read_string();
    auto quote = rr.read_blob();
    EXPECT_EQ(rr.remaining(), 0u);
    EXPECT_FALSE(out_bytes.empty());
    EXPECT_FALSE(tjson.empty());
    EXPECT_EQ(tjson.find("\"error\""), std::string::npos) << "server error: " << tjson;

    Transcript transcript = Transcript::from_json(tjson);
    Hash32 ek_hash = hash_concatenated(eval_keys);
    std::vector<Hash32> in_hashes;
    in_hashes.push_back(blake3_hash(input_ct_blobs[0]));
    Hash32 out_hash = blake3_hash(out_bytes);

    Verifier v;
    bool transcript_ok = v.verify_transcript(
        transcript, nonce, ek_hash, in_hashes, out_hash);
    EXPECT_TRUE(transcript_ok);

    (void)quote;

    auto out_ct = deserialize_ciphertext(std::string(out_bytes.begin(), out_bytes.end()));
    Plaintext pt_out;
    cc->Decrypt(kp.secretKey, out_ct, &pt_out);
    pt_out->SetLength(32);
    auto dec = pt_out->GetCKKSPackedValue();
    for (int i = 0; i < 32; ++i) {
        EXPECT_NEAR(dec[i].real(), 1.0, 1e-3);
    }
}

TEST(ClientLogic, TamperedTranscriptFailsVerify) {
    TCPServer srv("127.0.0.1", 0);
    uint16_t port = srv.port();
    ASSERT_NE(port, 0);
    std::atomic<bool> stop{false};
    std::thread srv_thread(run_dispatch_one, std::ref(srv), std::ref(stop));

    auto& registry = get_workload_registry();
    const Workload& workload = registry["noop"];
    auto cc = workload.make_context();
    auto kp = cc->KeyGen();
    cc->EvalMultKeyGen(kp.secretKey);
    std::ostringstream emk_oss(std::ios::binary);
    CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey(emk_oss, SerType::BINARY);
    std::string emk_s = emk_oss.str();
    std::vector<std::vector<uint8_t>> eval_keys;
    eval_keys.emplace_back(emk_s.begin(), emk_s.end());

    std::vector<double> vals(32, 1.0);
    auto pt = cc->MakeCKKSPackedPlaintext(vals);
    auto ct = cc->Encrypt(kp.publicKey, pt);
    std::string ct_s = serialize_ciphertext(ct);
    std::vector<std::vector<uint8_t>> input_ct_blobs;
    input_ct_blobs.emplace_back(ct_s.begin(), ct_s.end());

    auto nonce = random_nonce(16);
    BufWriter w;
    w.write_blob(nonce);
    w.write_u32_be((uint32_t)eval_keys.size());
    for (auto& k : eval_keys) w.write_blob(k);
    w.write_u32_be((uint32_t)input_ct_blobs.size());
    for (auto& c : input_ct_blobs) w.write_blob(c);
    w.write_string("noop");

    std::vector<uint8_t> resp;
    try {
        TCPClient cli("127.0.0.1", port);
        send_message(cli.fd(), w.data());
        resp = recv_message(cli.fd());
        cli.close();
    } catch (...) {
        stop.store(true);
        srv.close();
        try { TCPClient("127.0.0.1", port).close(); } catch (...) {}
        srv_thread.join();
        throw;
    }

    stop.store(true);
    srv.close();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    try { TCPClient("127.0.0.1", port).close(); } catch (...) {}
    srv_thread.join();

    BufReader rr(resp);
    auto out_bytes = rr.read_blob();
    auto tjson = rr.read_string();
    (void)rr.read_blob();

    auto tampered_out = out_bytes;
    tampered_out[0] ^= 0x01;
    Hash32 ek_hash = hash_concatenated(eval_keys);
    std::vector<Hash32> in_hashes;
    in_hashes.push_back(blake3_hash(input_ct_blobs[0]));
    Hash32 tampered_out_hash = blake3_hash(tampered_out);

    Transcript transcript = Transcript::from_json(tjson);
    Verifier v;
    bool bad = v.verify_transcript(
        transcript, nonce, ek_hash, in_hashes, tampered_out_hash);
    EXPECT_FALSE(bad);

    Hash32 good_out_hash = blake3_hash(out_bytes);
    bool good = v.verify_transcript(
        transcript, nonce, ek_hash, in_hashes, good_out_hash);
    EXPECT_TRUE(good);
}

TEST(ClientLogic, TeeClientBinaryExistsAndBuilds) {
    // tee_client is produced alongside test binaries; check a few likely paths.
    std::ifstream f1("./tee_client");
    std::ifstream f2("../tee_client");
    std::ifstream f3("../../tee_client");
    EXPECT_TRUE(f1.good() || f2.good() || f3.good())
        << "tee_client binary not found near test binary";
}
