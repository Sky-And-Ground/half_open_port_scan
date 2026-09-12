#include "syn_scan.h"
#include "scanner.h"
#include <algorithm>

std::vector<int> syn_scan(const char* src_ip, const char* dst_ip, int port_begin, int port_end, int timeout_ms) {
    // here we just create a port lists, except for the port begin to the port end, it can add some common ports, like 443, 3306, 8000.
    std::vector<int> port_list;
    for (int i = std::min(port_begin, port_end); i <= std::max(port_begin, port_end); ++i) {
        port_list.emplace_back(i);
    }

    Scanner scanner;
    return scanner.scan(src_ip, dst_ip, port_list, timeout_ms);
}