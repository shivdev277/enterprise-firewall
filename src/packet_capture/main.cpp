#include <iostream>
#include <pcap.h>

#include "../packet_parser/ethernet_parser.hpp"

int main() {
    char error_buffer[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(
        "eth0",
        65535,
        1,
        1000,
        error_buffer
    );

    if (handle == nullptr) {
        std::cerr << "Failed to open interface: "
                  << error_buffer << std::endl;
        return 1;
    }

    std::cout << "Firewall packet capture started on eth0"
              << std::endl;

    while (true) {
        struct pcap_pkthdr* packet_header;
        const u_char* packet_data;

        int result = pcap_next_ex(
            handle,
            &packet_header,
            &packet_data
        );

        if (result == 1) {
            EthernetHeader ethernet_header;

            bool parsed = parse_ethernet_header(
                packet_data,
                packet_header->caplen,
                ethernet_header
            );

            if (!parsed) {
                std::cout << "Packet too short for Ethernet header"
                          << std::endl;
                continue;
            }

            std::cout
                << "\nPacket captured"
                << "\n  Length: "
                << packet_header->caplen
                << " bytes"
                << "\n  Source MAC: "
                << mac_to_string(ethernet_header.source_mac)
                << "\n  Destination MAC: "
                << mac_to_string(ethernet_header.destination_mac)
                << "\n  EtherType: 0x"
                << std::hex
                << ethernet_header.ether_type
                << std::dec
                << std::endl;
        }
        else if (result == 0) {
            continue;
        }
        else if (result == -1) {
            std::cerr
                << "Capture error: "
                << pcap_geterr(handle)
                << std::endl;
            break;
        }
        else if (result == -2) {
            break;
        }
    }

    pcap_close(handle);

    return 0;
}
