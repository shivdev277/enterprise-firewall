#pragma once

#include <cstdint>
#include <string>

struct EthernetHeader {
    std::uint8_t destination_mac[6];
    std::uint8_t source_mac[6];
    std::uint16_t ether_type;
};

std::string mac_to_string(const std::uint8_t mac[6]);

bool parse_ethernet_header(
    const std::uint8_t* packet,
    std::size_t packet_length,
    EthernetHeader& header
);
