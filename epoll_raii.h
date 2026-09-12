#ifndef __EPOLL_RAII_H__
#define __EPOLL_RAII_H__

#include <sys/epoll.h>
#include <unistd.h>
#include <system_error>
#include <cerrno>

class Epoll {
public:
    Epoll() : fd{ -1 } {}

    Epoll(int flags) {
        fd = epoll_create1(flags);

        if (fd < 0) {
            std::error_code ec{ errno, std::system_category() };
            throw std::system_error{ ec, "sys call epoll_create1 failed" };
        }
    }

    Epoll(const Epoll&) = delete;
    Epoll& operator=(const Epoll&) = delete;

    Epoll(Epoll&& other) noexcept
        : fd{ other.fd }
    {
        other.fd = -1;
    }

    Epoll& operator=(Epoll&& other) noexcept {
        if (this != &other) {
            close();

            fd = other.fd;
            other.fd = -1;
        }

        return *this;
    }

    ~Epoll() {
        if (fd >= 0) {
            close(fd);
        }
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