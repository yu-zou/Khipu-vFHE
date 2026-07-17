#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tee {

// RAII wrapper around a POSIX socket file descriptor. Closes the fd on
// destruction unless release() was called. Move-only.
class Socket {
public:
    Socket() : fd_(-1) {}
    explicit Socket(int fd) : fd_(fd) {}
    ~Socket();

    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    Socket(Socket&& other) noexcept : fd_(other.fd_) { other.fd_ = -1; }
    Socket& operator=(Socket&& other) noexcept;

    int fd() const { return fd_; }
    bool valid() const { return fd_ >= 0; }

    // Return and abandon ownership of the fd (destructor will not close it).
    int release();

    // Close the fd now; safe to call multiple times.
    void close();

private:
    int fd_;
};

// A listening TCP server. Binds on construction; accept() returns a connected
// Socket. Use port() to retrieve the actually bound port (useful when
// constructed with port 0 for OS-assigned ports).
class TCPServer {
public:
    // host: e.g. "127.0.0.1" or "0.0.0.0". port: 0 for any available port.
    TCPServer(const std::string& host, uint16_t port);
    ~TCPServer();

    TCPServer(const TCPServer&) = delete;
    TCPServer& operator=(const TCPServer&) = delete;

    // Block until an incoming connection arrives; returns an RAII Socket.
    Socket accept();

    // The port this server is listening on (after getsockname).
    uint16_t port() const { return port_; }

    // Close the listening socket; safe to call multiple times.
    void close();

private:
    int listen_fd_;
    uint16_t port_;
};

// An outbound TCP client connection.
class TCPClient {
public:
    TCPClient() = default;
    // Convenience constructor: calls connect(host, port).
    TCPClient(const std::string& host, uint16_t port);
    ~TCPClient();

    TCPClient(const TCPClient&) = delete;
    TCPClient& operator=(const TCPClient&) = delete;

    // Connect to host:port. Throws std::runtime_error on failure. Must not
    // already be connected.
    void connect(const std::string& host, uint16_t port);

    int fd() const { return sock_.fd(); }

    void close();

private:
    Socket sock_;
};

// Send a length-prefixed message: 4-byte big-endian length followed by the
// payload. Loops until all bytes are sent; retries on EINTR. Throws
// std::runtime_error on send failure or short write.
void send_message(int sock, const std::vector<uint8_t>& payload);
void send_message(int sock, const uint8_t* data, size_t len);

// Receive a length-prefixed message: reads 4-byte BE length, then the payload.
// Loops until complete; retries on EINTR. Throws std::runtime_error on EOF
// (peer closed cleanly before a full message arrived) or error.
std::vector<uint8_t> recv_message(int sock);

}  // namespace tee
