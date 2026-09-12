#include <iostream>
#include <system_error>
#include "syn_scan.h"

/*
    compile with:
        g++ main.cpp syn_scan.cpp -std=c++11
    
    running this program should be with root. because this program uses the raw socket, so may be we have to set the firewall:
        iptables -I OUTPUT -s 192.168.52.114 -d 192.168.58.33 -j ACCEPT
*/
int main(int argc, char* argv[]) {
    try {
        auto opened_ports = syn_scan("192.168.52.114", "192.168.58.33", 8000, 10000, 3000);

        for (int i : opened_ports) {
            std::cout << i << " ";
        }

        std::cout << "\n";
    }
    catch(const std::system_error& e) {
        std::cerr << "system error, " << e.code().value() << ", " << e.what() << "\n";
    }

    return 0;
}
