cmake_minimum_required(VERSION 3.16)

project(EnterpriseFirewall
    VERSION 1.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_library(PCAP_LIBRARY pcap REQUIRED)

add_executable(packet_capture
    source/packet_capture.cpp
)

target_link_libraries(packet_capture
    PRIVATE
    ${PCAP_LIBRARY}
)

