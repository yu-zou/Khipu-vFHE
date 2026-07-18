#include "common/tcp_transport.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstring>
#include <stdexcept>
#include <string>

namespace tee {

namespace {

// Helper: write all `len` bytes from `buf` to `sock`, looping on EINTR and
// short writes. Throws on actual error.
void write_all(int sock, const uint8_t* buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = ::send(sock, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error(std::string("send failed: ") +
                                     std::strerror(errno));
        }
        if (n == 0) {
            throw std::runtime_error(
                "send failed: peer closed connection during write");
        }
        sent += static_cast<size_t>(n);
    }
}

// Helper: read exactly `len` bytes into `buf`, looping on EINTR and short
// reads. Returns 0 on clean EOF before any bytes arrive; throws on EOF in the
// middle of a message; returns len on success.
size_t read_all(int sock, uint8_t* buf, size_t len, bool throw_on_eof_mid) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = ::recv(sock, buf + got, len - got, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error(std::string("recv failed: ") +
                                     std::strerror(errno));
        }
        if (n == 0) {
            if (got == 0 && !throw_on_eof_mid) {
                return 0;  // clean EOF at a message boundary (not used here)
            }
            throw std::runtime_error(
                "recv failed: unexpected EOF from peer (truncated message)");
        }
        got += static_cast<size_t>(n);
    }
    return got;
}

}  // namespace

// ── Socket ────────────────────────────────────────────────────────────────

Socket::~Socket() { close(); }

Socket& Socket::operator=(Socket&& other) noexcept {
    if (this != &other) {
        close();
        fd_ = other.fd_;
        other.fd_ = -1;
    }
    return *this;
}

int Socket::release() {
    int fd = fd_;
    fd_ = -1;
    return fd;
}

void Socket::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

// ── TCPServer ─────────────────────────────────────────────────────────────

TCPServer::TCPServer(const std::string& host, uint16_t port)
    : listen_fd_(-1), port_(0) {
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo* res = nullptr;
    std::string port_str = std::to_string(port);
    int rc = ::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
    if (rc != 0) {
        throw std::runtime_error(std::string("getaddrinfo failed: ") +
                                 gai_strerror(rc));
    }

    int fd = -1;
    struct addrinfo* rp = nullptr;
    for (rp = res; rp != nullptr; rp = rp->ai_next) {
        fd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        int yes = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        if (::bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;  // success
        }
        ::close(fd);
        fd = -1;
    }
    if (fd < 0) {
        ::freeaddrinfo(res);
        throw std::runtime_error(std::string("bind to ") + host + ":" +
                                 port_str + " failed");
    }

    if (::listen(fd, 128) < 0) {
        int saved_errno = errno;
        ::close(fd);
        ::freeaddrinfo(res);
        throw std::runtime_error(std::string("listen failed: ") +
                                 std::strerror(saved_errno));
    }

    // Determine actual bound port (covers port==0 auto-assignment).
    struct sockaddr_storage bound_addr;
    socklen_t bound_len = sizeof(bound_addr);
    if (::getsockname(fd, reinterpret_cast<struct sockaddr*>(&bound_addr),
                      &bound_len) == 0) {
        if (bound_addr.ss_family == AF_INET) {
            auto* sin =
                reinterpret_cast<const struct sockaddr_in*>(&bound_addr);
            port_ = ntohs(sin->sin_port);
        } else if (bound_addr.ss_family == AF_INET6) {
            auto* sin6 =
                reinterpret_cast<const struct sockaddr_in6*>(&bound_addr);
            port_ = ntohs(sin6->sin6_port);
        }
    }
    if (port_ == 0) {
        port_ = port;  // fallback to what caller asked
    }

    ::freeaddrinfo(res);
    listen_fd_ = fd;
}

TCPServer::~TCPServer() { close(); }

Socket TCPServer::accept() {
    if (listen_fd_ < 0) {
        throw std::runtime_error("accept called on closed server");
    }
    struct sockaddr_storage peer_addr;
    socklen_t peer_len = sizeof(peer_addr);
    for (;;) {
        int client_fd =
            ::accept(listen_fd_, reinterpret_cast<struct sockaddr*>(&peer_addr),
                     &peer_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error(std::string("accept failed: ") +
                                     std::strerror(errno));
        }
        return Socket(client_fd);
    }
}

void TCPServer::close() {
    if (listen_fd_ >= 0) {
        ::close(listen_fd_);
        listen_fd_ = -1;
    }
}

// ── TCPClient ─────────────────────────────────────────────────────────────

TCPClient::TCPClient(const std::string& host, uint16_t port) { connect(host, port); }

TCPClient::~TCPClient() = default;

void TCPClient::connect(const std::string& host, uint16_t port) {
    if (sock_.valid()) {
        throw std::runtime_error("TCPClient::connect called while already connected");
    }

    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* res = nullptr;
    std::string port_str = std::to_string(port);
    int rc = ::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
    if (rc != 0) {
        throw std::runtime_error(std::string("getaddrinfo failed: ") +
                                 gai_strerror(rc));
    }

    int fd = -1;
    struct addrinfo* rp = nullptr;
    for (rp = res; rp != nullptr; rp = rp->ai_next) {
        fd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (::connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        ::close(fd);
        fd = -1;
    }
    ::freeaddrinfo(res);
    if (fd < 0) {
        throw std::runtime_error(std::string("connect to ") + host + ":" +
                                 port_str + " failed");
    }
    sock_ = Socket(fd);
}

void TCPClient::close() { sock_.close(); }

// ── Message framing ───────────────────────────────────────────────────────

void send_message(int sock, const std::vector<uint8_t>& payload) {
    send_message(sock, payload.data(), payload.size());
}

void send_message(int sock, const uint8_t* data, size_t len) {
    // Use 8-byte length prefix (big-endian) to support payloads >4GB
    uint64_t orig_len = len;
    uint8_t net_len[8];
    for (int i = 7; i >= 0; i--) {
        net_len[i] = static_cast<uint8_t>(orig_len & 0xFF);
        orig_len >>= 8;
    }
    write_all(sock, net_len, 8);
    if (len > 0) {
        write_all(sock, data, len);
    }
}

std::vector<uint8_t> recv_message(int sock) {
    // Read 8-byte length prefix (big-endian)
    uint8_t net_len[8];
    size_t got = read_all(sock, net_len, 8, /*throw_on_eof_mid=*/true);
    if (got == 0) {
        return {};
    }
    uint64_t len = 0;
    for (int i = 0; i < 8; i++) {
        len = (len << 8) | net_len[i];
    }
    std::vector<uint8_t> buf(static_cast<size_t>(len));
    if (len > 0) {
        read_all(sock, buf.data(), static_cast<size_t>(len), /*throw_on_eof_mid=*/true);
    }
    return buf;
}

}  // namespace tee
