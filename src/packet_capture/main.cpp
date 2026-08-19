#include <iostream>
#include <pcap.h>

#include "../packet_parser/ethernet_parser.hpp"
#include "../packet_parser/ipv4_parser.hpp"

int main() {
    constexpr char INTERFACE[] = "eth0";
    constexpr int SNAPSHOT_LENGTH = 65535;
    constexpr int PROMISCUOUS_MODE = 1;
    constexpr int CAPTURE_TIMEOUT_MS = 1000;

    char error_buffer[PCAP_ERRBUF_SIZE];

    // Open the network interface for packet capture.
    pcap_t* handle = pcap_open_live(
        INTERFACE,
        SNAPSHOT_LENGTH,
        PROMISCUOUS_MODE,
        CAPTURE_TIMEOUT_MS,
        error_buffer
    );

    if (handle == nullptr) {
        std::cerr
            << "Failed to open interface "
            << INTERFACE
            << ": "
            << error_buffer
            << std::endl;

        return 1;
    }

    std::cout
        << "Firewall packet capture started on "
        << INTERFACE
        << std::endl;

    while (true) {
        struct pcap_pkthdr* packet_header = nullptr;
        const u_char* packet_data = nullptr;

        int result = pcap_next_ex(
            handle,
            &packet_header,
            &packet_data
        );

        // A packet was captured.
        if (result == 1) {

            EthernetHeader ethernet_header{};

            bool ethernet_parsed = parse_ethernet_header(
                packet_data,
                packet_header->caplen,
                ethernet_header
            );

            if (!ethernet_parsed) {
                std::cout
                    << "Packet too short for Ethernet header"
                    << std::endl;

                continue;
            }

            std::cout
                << "\n========================================"
                << "\nPacket captured"
                << "\n========================================"
                << "\nLength: "
                << packet_header->caplen
                << " bytes"

                << "\n\nEthernet"
                << "\n  Source MAC: "
                << mac_to_string(
                    ethernet_header.source_mac
                )

                << "\n  Destination MAC: "
                << mac_to_string(
                    ethernet_header.destination_mac
                )

                << "\n  EtherType: 0x"
                << std::hex
                << ethernet_header.ether_type
                << std::dec;

            /*
             * EtherType 0x0800 means IPv4.
             */
            if (ethernet_header.ether_type == 0x0800) {

                constexpr std::size_t ETHERNET_HEADER_SIZE = 14;

                // Make sure enough bytes remain after Ethernet.
                if (packet_header->caplen <=
                    ETHERNET_HEADER_SIZE) {

                    std::cout
                        << "\n\nIPv4"
                        << "\n  Packet too short";

                    continue;
                }

                IPv4Header ipv4_header{};

                bool ipv4_parsed = parse_ipv4_header(
                    packet_data + ETHERNET_HEADER_SIZE,
                    packet_header->caplen -
                        ETHERNET_HEADER_SIZE,
                    ipv4_header
                );

                if (ipv4_parsed) {

                    std::cout
                        << "\n\nIPv4"

                        << "\n  Version: "
                        << static_cast<int>(
                            ipv4_header.version
                        )

                        << "\n  Header Length: "
                        << static_cast<int>(
                            ipv4_header.header_length
                        )
                        << " bytes"

                        << "\n  Total Length: "
                        << ipv4_header.total_length
                        << " bytes"

                        << "\n  TTL: "
                        << static_cast<int>(
                            ipv4_header.ttl
                        )

                        << "\n  Protocol: "
                        << static_cast<int>(
                            ipv4_header.protocol
                        )

                        << "\n  Source IP: "
                        << ipv4_to_string(
                            ipv4_header.source_ip
                        )

                        << "\n  Destination IP: "
                        << ipv4_to_string(
                            ipv4_header.destination_ip
                        );
                }
                else {

                    std::cout
                        << "\n\nIPv4"
                        << "\n  IPv4 parsing failed";
                }
            }

            /*
             * EtherType 0x0806 means ARP.
             */
            else if (ethernet_header.ether_type == 0x0806) {

                std::cout
                    << "\n\nProtocol"
                    << "\n  ARP";
            }

            /*
             * EtherType 0x86DD means IPv6.
             */
            else if (ethernet_header.ether_type == 0x86DD) {

                std::cout
                    << "\n\nProtocol"
                    << "\n  IPv6";
            }

            /*
             * Unknown EtherType.
             */
            else {

                std::cout
                    << "\n\nProtocol"
                    << "\n  Unknown EtherType";
            }

            std::cout << std::endl;
        }

        // Capture timeout.
        else if (result == 0) {
            continue;
        }

        // Capture error.
        else if (result == -1) {

            std::cerr
                << "Capture error: "
                << pcap_geterr(handle)
                << std::endl;

            break;
        }

        // No more packets / offline capture ended.
        else if (result == -2) {
            break;
        }
    }

    pcap_close(handle);

    return 0;
}
