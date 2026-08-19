#include "ipv4_parser.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <sstream>

bool parse_ipv4_header(
    const std::uint8_t* packet,
    std::size_t packet_length,
    IPv4Header& header
) {
    constexpr std::size_t MIN_IPV4_HEADER_SIZE = 20;

    if (packet == nullptr ||
        packet_length < MIN_IPV4_HEADER_SIZE) {
        return false;
    }

    std::uint8_t version_and_ihl = packet[0];

    header.version = (version_and_ihl >> 4) & 0x0F;

    std::uint8_t ihl = version_and_ihl & 0x0F;

    header.header_length = ihl * 4;

    if (header.version != 4 ||
        header.header_length < MIN_IPV4_HEADER_SIZE ||
        packet_length < header.header_length) {
        return false;
    }

    std::uint16_t network_total_length;
    std::memcpy(
        &network_total_length,
        packet + 2,
        sizeof(network_total_length)
    );

    header.total_length = ntohs(network_total_length);

    std::uint16_t network_identification;
    std::memcpy(
        &network_identification,
        packet + 4,
        sizeof(network_identification)
    );

    header.identification = ntohs(network_identification);

    std::uint16_t network_flags_fragment;
    std::memcpy(
        &network_flags_fragment,
        packet + 6,
        sizeof(network_flags_fragment)
    );

    header.flags_fragment_offset = ntohs(network_flags_fragment);

    header.ttl = packet[8];

    header.protocol = packet[9];

    std::uint32_t network_source_ip;
    std::memcpy(
        &network_source_ip,
        packet + 12,
        sizeof(network_source_ip)
    );

    header.source_ip = network_source_ip;

    std::uint32_t network_destination_ip;
    std::memcpy(
        &network_destination_ip,
        packet + 16,
        sizeof(network_destination_ip)
    );

    header.destination_ip = network_destination_ip;

    return true;
}

std::string ipv4_to_string(std::uint32_t ip) {
    struct in_addr address;

    address.s_addr = ip;

    char buffer[INET_ADDRSTRLEN];

    if (inet_ntop(
            AF_INET,
            &address,
            buffer,
            sizeof(buffer)
        ) == nullptr) {
        return "INVALID";
    }

    return std::string(buffer);
}
