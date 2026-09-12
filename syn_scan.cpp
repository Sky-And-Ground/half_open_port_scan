#include "syn_scan.h"
#include "socket_raii.h"
#include <random>
#include <system_error>
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/time.h>

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

    bool recv_response(int sock, const char* src_ip, const char* dst_ip, int src_port, int dst_port, int id) {
        char buffer[4096];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);

        struct in_addr dst_addr;
        inet_pton(AF_INET, dst_ip, &dst_addr);

        while (true) {
            int len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&from, &from_len);

            if (len < 0) {  // timeout or something error would break this loop.
                return false;
            }

            struct iphdr* iph = (struct iphdr*)buffer;
            
            if (iph->protocol != IPPROTO_TCP) {
                continue;
            }

            struct tcphdr* tcph = (struct tcphdr*)(buffer + 4 * iph->ihl);

            if (ntohs(tcph->source) != dst_port) {
                continue;
            }

            if (from.sin_addr.s_addr != dst_addr.s_addr) {
                continue;
            }

            if (tcph->syn && tcph->ack) {
                uint32_t rseq = ntohl(tcph->ack_seq);
                uint32_t rack_seq = ntohl(tcph->seq) + 1;

                send_tcp_packet(sock, src_ip, dst_ip, src_port, dst_port, id, rseq, rack_seq, false, true, true);
                return true;
            }

            if (tcph->rst) {
                return false;
            }
        }
    }
}

std::vector<int> syn_scan(const char* src_ip, const char* dst_ip, int port_begin, int port_end, int timeout_ms) {
    // using raw socket.
    Socket sock { AF_INET, SOCK_RAW, IPPROTO_TCP };

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    if (setsockopt(sock.handle(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        std::error_code ec{ errno, std::system_category() };
        throw std::system_error{ ec, "sys call setsockopt() failed on SO_RCVTIMEO" };
    }

    int flag = 1;
    if (setsockopt(sock.handle(), IPPROTO_IP, IP_HDRINCL, &flag, sizeof(flag)) < 0) {
        std::error_code ec{ errno, std::system_category() };
        throw std::system_error{ ec, "sys call setsockopt() failed on IP_HDRINCL" };
    }

    // to generate random id and  source port. 
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 65535);

    // here we just create a port lists, except for the port begin to the port end, it can add some common ports, like 443, 3306, 8000.
    std::vector<int> port_lists;
    for (int i = std::min(port_begin, port_end); i <= std::max(port_begin, port_end); ++i) {
        port_lists.emplace_back(i);
    }

    std::vector<int> opened_ports;

    for (int dst_port : port_lists) {
        int id = dist(gen);
        int src_port = 30000 + dist(gen) % 30000;   // every scan just uses a random port.
        
        if (!send_tcp_packet(sock.handle(), src_ip, dst_ip, src_port, dst_port, id, id, 0, true, false, false)) {
            continue;
        }

        if (recv_response(sock.handle(), src_ip, dst_ip, src_port, dst_port, id)) {
            opened_ports.emplace_back(dst_port);
        }
    }

    return opened_ports;
}