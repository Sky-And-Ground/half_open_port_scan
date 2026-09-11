#ifndef __SYN_SCAN_H__
#define __SYN_SCAN_H__

#include <vector>

std::vector<int> syn_scan(const char* src_ip, const char* dst_ip, int port_begin, int port_end, int timeout_ms);

#endif