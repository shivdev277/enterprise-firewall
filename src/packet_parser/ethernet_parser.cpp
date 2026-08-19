#include "ethernet_parser.hpp"

#include <cstring>
#include <iomanip>
#include <sstream>

#include <arpa/inet.h>

std::string mac_to_string(const std::uint8_t mac[6]) {
    std::ostringstream output;

    output << std::hex
           << std::setfill('0');

    for (int i = 0; i < 6; ++i) {
        if (i > 0) {
            output << ":";
        }

        output << std::setw(2)
               << static_cast<int>(mac[i]);
    }

    return output.str();
}

bool parse_ethernet_header(
    const std::uint8_t* packet,
    std::size_t packet_length,
    EthernetHeader& header
) {
    constexpr std::size_t ETHERNET_HEADER_SIZE = 14;

    if (packet == nullptr ||
        packet_length < ETHERNET_HEADER_SIZE) {
        return false;
    }

    std::memcpy(
        header.destination_mac,
        packet,
        6
    );

    std::memcpy(
        header.source_mac,
        packet + 6,
        6
    );

    std::uint16_t network_ether_type;

    std::memcpy(
        &network_ether_type,
        packet + 12,
        sizeof(network_ether_type)
    );

    header.ether_type = ntohs(network_ether_type);

    return true;
}
