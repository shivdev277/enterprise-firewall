#include <iostream>
#include <pcap.h>

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
            std::cout
                << "Packet captured! "
                << "Length: "
                << packet_header->caplen
                << " bytes"
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
