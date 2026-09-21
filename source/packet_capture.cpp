#include <iostream>
#include <iomanip>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

void print_mac(const u_char* mac)
{
    for (int i = 0; i < 6; i++)
    {
        if (i != 0)
            std::cout << ":";

        std::cout << std::hex
                  << std::setw(2)
                  << std::setfill('0')
                  << static_cast<int>(mac[i]);
    }

    std::cout << std::dec;
}

int main()
{
    char error_buffer[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(
        "eth0",
        65536,
        1,
        1000,
        error_buffer
    );

    if (handle == nullptr)
    {
        std::cerr << "Error opening eth0: "
                  << error_buffer << std::endl;

        return 1;
    }

    std::cout << "Packet capture started on eth0...\n";
    std::cout << "Waiting for packets...\n\n";

    struct pcap_pkthdr* header;
    const u_char* packet;

    while (true)
    {
        int result = pcap_next_ex(
            handle,
            &header,
            &packet
        );

        if (result == 1)
        {
            std::cout << "\n========================================\n";
            std::cout << "Packet captured\n";
            std::cout << "========================================\n";

            std::cout << "Length: "
                      << header->len
                      << " bytes\n\n";

            // Ethernet Header
            const u_char* destination_mac = packet;
            const u_char* source_mac = packet + 6;

            uint16_t ether_type =
                (static_cast<uint16_t>(packet[12]) << 8) |
                static_cast<uint16_t>(packet[13]);

            std::cout << "Ethernet\n";

            std::cout << "  Source MAC:      ";
            print_mac(source_mac);
            std::cout << "\n";

            std::cout << "  Destination MAC: ";
            print_mac(destination_mac);
            std::cout << "\n";

            std::cout << "  EtherType:       0x"
                      << std::hex
                      << std::setw(4)
                      << std::setfill('0')
                      << ether_type
                      << std::dec
                      << "\n";

            // IPv4
            if (ether_type == 0x0800)
            {
                const struct ip* ip_header =
                    reinterpret_cast<const struct ip*>(
                        packet + 14
                    );

                char source_ip[INET_ADDRSTRLEN];
                char destination_ip[INET_ADDRSTRLEN];

                inet_ntop(
                    AF_INET,
                    &(ip_header->ip_src),
                    source_ip,
                    INET_ADDRSTRLEN
                );

                inet_ntop(
                    AF_INET,
                    &(ip_header->ip_dst),
                    destination_ip,
                    INET_ADDRSTRLEN
                );

                std::cout << "\nIPv4\n";

                std::cout << "  Version:          "
                          << static_cast<int>(ip_header->ip_v)
                          << "\n";

                std::cout << "  Header Length:    "
                          << (ip_header->ip_hl * 4)
                          << " bytes\n";

                std::cout << "  Source IP:        "
                          << source_ip
                          << "\n";

                std::cout << "  Destination IP:   "
                          << destination_ip
                          << "\n";

                std::cout << "  TTL:              "
                          << static_cast<int>(ip_header->ip_ttl)
                          << "\n";

                std::cout << "  Protocol:         "
                          << static_cast<int>(ip_header->ip_p)
                          << "\n";

                // Calculate where the transport header starts
                const u_char* transport_header =
                    packet + 14 + (ip_header->ip_hl * 4);

                // TCP
                if (ip_header->ip_p == IPPROTO_TCP)
                {
                    const struct tcphdr* tcp_header =
                        reinterpret_cast<const struct tcphdr*>(
                            transport_header
                        );

                    std::cout << "\nTCP\n";

                    std::cout << "  Source Port:      "
                              << ntohs(tcp_header->source)
                              << "\n";

                    std::cout << "  Destination Port: "
                              << ntohs(tcp_header->dest)
                              << "\n";
                }

                // UDP
                else if (ip_header->ip_p == IPPROTO_UDP)
                {
                    const struct udphdr* udp_header =
                        reinterpret_cast<const struct udphdr*>(
                            transport_header
                        );

                    std::cout << "\nUDP\n";

                    std::cout << "  Source Port:      "
                              << ntohs(udp_header->source)
                              << "\n";

                    std::cout << "  Destination Port: "
                              << ntohs(udp_header->dest)
                              << "\n";
                }

                // ICMP
                else if (ip_header->ip_p == IPPROTO_ICMP)
                {
                    std::cout << "\nICMP\n";
                }

                else
                {
                    std::cout << "\nOther IPv4 protocol\n";
                }
            }
            else if (ether_type == 0x0806)
            {
                std::cout << "\nARP\n";
            }
            else
            {
                std::cout << "\nOther Ethernet protocol\n";
            }
        }
        else if (result == 0)
        {
            continue;
        }
        else if (result == -1)
        {
            std::cerr << "Error reading packet: "
                      << pcap_geterr(handle)
                      << std::endl;

            break;
        }
        else if (result == -2)
        {
            break;
        }
    }

    pcap_close(handle);

    return 0;
}
