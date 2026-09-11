#ifndef __SOCKET_RAII_H__
#define __SOCKET_RAII_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <system_error>
#include <cerrno>

class Socket {
public:
    Socket() : fd{ -1 } {}

    Socket(int domain, int type, int protocol) {
        fd = ::socket(domain, type, protocol);

        if (fd < 0) {
            std::error_code ec{ errno, std::system_category() };
            throw std::system_error{ ec, "sys call socket() failed" };
        }
    }

    ~Socket() {
        close();
    }

    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    Socket(Socket&& other) noexcept : fd { other.fd } {
        other.fd = -1;
    }

    Socket& operator=(Socket&& other) noexcept {
        if (this != &other) {
            close();

            fd = other.fd;
            other.fd = -1;
        }

        return *this;
    }

    void close() noexcept {
        if (fd >= 0) {
            ::close(fd);
            fd = -1;
        }
    }

    int handle() const noexcept {
        return fd;
    }
private:
    int fd;
};

#endif