#ifndef __SCANNER_H__
#define __SCANNER_H__

#include "socket_raii.h"
#include "epoll_raii.h"
#include <random>
#include <system_error>
#include <vector>

class RandomIntegerGenerator {
public:
    RandomIntegerGenerator() = default;

    int operator()() {
        return dist(gen);
    }
private:
    std::random_device rd;
    std::mt19937 gen{ rd() };
    std::uniform_int_distribution<int> dist{ 0, 65535 };
};

class Scanner {
public:
    Scanner(int timeout_ms);

    std::vector<int> scan(const char* src_ip, const char* dst_ip, const std::vector<int>& port_list);
private:
    Socket sock;
    Epoll epoll;
    RandomIntegerGenerator randgen;
};

#endif
