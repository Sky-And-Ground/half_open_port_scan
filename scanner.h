#ifndef __SCANNER_H__
#define __SCANNER_H__

#include "socket_raii.h"
#include "epoll_raii.h"
#include <system_error>
#include <vector>

class Scanner {
public:
    Scanner();

    std::vector<int> scan(const char* src_ip, const char* dst_ip, const std::vector<int>& port_list, int timeout_ms);
private:
    Socket sock;
    Epoll epoll;
};

#endif
