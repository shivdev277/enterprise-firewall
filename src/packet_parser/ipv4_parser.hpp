#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

struct IPv4Header {
    std::uint8_t version;
    std::uint8_t header_length;
    std::uint8_t ttl;
    std::uint8_t protocol;

    std::uint16_t total_length;
    std::uint16_t identification;
    std::uint16_t flags_fragment_offset;

    std::uint32_t source_ip;
    std::uint32_t destination_ip;
};

bool parse_ipv4_header(
    const std::uint8_t* packet,
    std::size_t packet_length,
    IPv4Header& header
);

std::string ipv4_to_string(std::uint32_t ip);
