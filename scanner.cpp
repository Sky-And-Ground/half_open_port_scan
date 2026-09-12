#include "scanner.h"
#include <chrono>
#include <unordered_set>
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <fcntl.h>

using namespace std::chrono;

namespace {
    struct PseudoHeader {
        uint32_t src_address;
        uint32_t dst_address;
        uint8_t placeholder;
        uint8_t protocol;
        uint16_t tcp_length;
    };

    uint16_t checksum(uint16_t* ptr, int nbytes) {
        uint32_t sum = 0;
        
        while (nbytes > 1) {
            sum += *ptr;
            ++ptr;
            nbytes -= 2;
        }

        if (nbytes == 1) {
            sum += *(uint8_t*)ptr;
        }

        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        return (uint16_t)(~sum);
    }

    void fill_tcphdr_checksum(struct tcphdr* tcph, const char* src_ip, const char* dst_ip) {
        struct in_addr src_addr, dst_addr;
        inet_pton(AF_INET, src_ip, &src_addr);
        inet_pton(AF_INET, dst_ip, &dst_addr);

        PseudoHeader psh;
        psh.src_address = src_addr.s_addr;
        psh.dst_address = dst_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr));
        
        char tmp[sizeof(PseudoHeader) + sizeof(struct tcphdr)];
        memcpy(tmp, &psh, sizeof(psh));
        memcpy(tmp + sizeof(psh), tcph, sizeof(struct tcphdr));

        tcph->check = checksum((uint16_t*)tmp, sizeof(tmp));
    }

    bool send_tcp_packet(int sock, const char* src_ip, const char* dst_ip, int src_port, int dst_port, int id, int seq, int ack_seq, bool syn, bool rst, bool ack) {
        char packet[4096];
        memset(packet, 0, sizeof(packet));

        struct iphdr* iph = (struct iphdr*)packet;
        struct tcphdr* tcph = (struct tcphdr*)(packet + sizeof(struct iphdr));

        struct in_addr src_addr, dst_addr;
        inet_pton(AF_INET, src_ip, &src_addr);
        inet_pton(AF_INET, dst_ip, &dst_addr);

        // ip header.
        iph->ihl      = 5;
        iph->version  = 4;   // ipv4.
        iph->tos      = 0;
        iph->tot_len  = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
        iph->id       = id;
        iph->frag_off = 0;
        iph->ttl      = 64;
        iph->protocol = IPPROTO_TCP;
        iph->saddr    = src_addr.s_addr;
        iph->daddr    = dst_addr.s_addr;
        iph->check    = checksum((uint16_t*)iph, sizeof(struct iphdr));

        // tcp header.
        tcph->source  = htons(src_port);
        tcph->dest    = htons(dst_port);
        tcph->seq     = htonl(seq);
        tcph->ack_seq = htonl(ack_seq);
        tcph->doff    = 5;
        tcph->fin     = 0;
        tcph->syn     = syn ? 1 : 0;
        tcph->rst     = rst ? 1 : 0;
        tcph->psh     = 0;
        tcph->ack     = rst ? 1 : 0;
        tcph->urg     = 0;
        tcph->window  = htons(65535);
        tcph->urg_ptr = 0;

        fill_tcphdr_checksum(tcph, src_ip, dst_ip);

        // now we can send it.
        struct sockaddr_in dst_in;
        dst_in.sin_family = AF_INET;
        dst_in.sin_addr = dst_addr;

        return sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr*)&dst_in, sizeof(dst_in)) >= 0;
    }

    void recv_response(int sock, const char* src_ip, const char* dst_ip, std::vector<int>& opened_ports, std::unordered_set<int> sent_ports) {
        char buffer[4096];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);

        struct in_addr dst_addr;
        inet_pton(AF_INET, dst_ip, &dst_addr);

        while (true) {
            int len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&from, &from_len);

            if (len < 0) {  // timeout or something error would break this loop.
                return;
            }

            struct iphdr* iph = (struct iphdr*)buffer;
            
            if (iph->protocol != IPPROTO_TCP) {
                continue;
            }

            if (from.sin_addr.s_addr != dst_addr.s_addr) {
                continue;
            }

            struct tcphdr* tcph = (struct tcphdr*)(buffer + 4 * iph->ihl);
            int dst_port = ntohs(tcph->source);

            auto iter = sent_ports.find(dst_port);
            if (iter == sent_ports.cend()) {
                continue;
            }

            int src_port = ntohs(tcph->dest);

            if (tcph->syn && tcph->ack) {
                uint32_t rseq = ntohl(tcph->ack_seq);
                uint32_t rack_seq = ntohl(tcph->seq) + 1;

                send_tcp_packet(sock, src_ip, dst_ip, src_port, dst_port, iph->id, rseq, rack_seq, false, true, true);
                opened_ports.emplace_back(dst_port);
                sent_ports.erase(iter);
            }

            if (tcph->rst) {
                sent_ports.erase(iter);
            }
        }
    }
}

Scanner::Scanner() 
    : sock { AF_INET, SOCK_RAW, IPPROTO_TCP }, epoll{ 0 }
{
    int flag = 1;
    if (setsockopt(sock.handle(), IPPROTO_IP, IP_HDRINCL, &flag, sizeof(flag)) < 0) {
        std::error_code ec{ errno, std::system_category() };
        throw std::system_error{ ec, "sys call setsockopt() failed on IP_HDRINCL" };
    }

    // let sock become non blocking, to deal with the epoll ET mode.
    flag = fcntl(sock.handle(), F_GETFL, 0);
    if (flag < 0) {
        std::error_code ec{ errno, std::system_category() };
        throw std::system_error{ ec, "sys call fcntl() failed on F_GETFL" };
    }

    if (fcntl(sock.handle(), F_SETFL, flag | O_NONBLOCK) < 0) {
        std::error_code ec{ errno, std::system_category() };
        throw std::system_error{ ec, "sys call fcntl() failed on F_SETFL and O_NONBLOCK" };
    }

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));

    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = sock.handle();

    if (epoll_ctl(epoll.handle(), EPOLL_CTL_ADD, sock.handle(), &ev) < 0) {
        std::error_code ec{ errno, std::system_category() };
        throw std::system_error{ ec, "sys call epoll_ctl failed on EPOLL_CTL_ADD with socket fd" };
    }
}

std::vector<int> Scanner::scan(const char* src_ip, const char* dst_ip, const std::vector<int>& port_list, int timeout_ms) {
    constexpr size_t batch_size = 1024;
    std::vector<int> opened_ports;

    for (size_t i = 0; i < port_list.size(); i += batch_size) {
        std::unordered_set<int> sent_ports;
        int start_id = 30000;
        int j;

        for (j = 0; (i + j) < port_list.size(); ++j) {
            int id = start_id + j;
            int src_port = id;
            int dst_port = port_list[i + j];

            if (send_tcp_packet(sock.handle(), src_ip, dst_ip, src_port, dst_port, id, id, 0, true, false, false)) {
                sent_ports.emplace(dst_port);
            }
        }

        auto deadline = steady_clock::now() + milliseconds(timeout_ms);
        struct epoll_event events[batch_size];

        while (!sent_ports.empty()) {
            auto now = steady_clock::now();
            
            if (now > deadline) {
                break;
            }

            auto wait_ms = duration_cast<milliseconds>(deadline - now).count();
            int n = epoll_wait(epoll.handle(), events, batch_size, (int)wait_ms);

            if (n < 0) {
                std::error_code ec{ errno, std::system_category() };
                throw std::system_error{ ec, "sys call epoll_wait failed" };
            }
            else if (n == 0) {   // time out.
                break;
            }

            for (int i = 0; i < n; ++i) {
                if ((events[i].events & EPOLLIN)) {
                    recv_response(sock.handle(), src_ip, dst_ip, opened_ports, sent_ports);
                }
            }
        }

        sent_ports.clear();
    }

    std::sort(opened_ports.begin(), opened_ports.end());
    opened_ports.erase(std::unique(opened_ports.begin(), opened_ports.end()), opened_ports.end());
    return opened_ports;
}