#include <iostream>
#include <pcap.h>

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
            std::cout << "========================================\n";
            std::cout << "Packet captured\n";
            std::cout << "Length: "
                      << header->len
                      << " bytes\n";
            std::cout << "========================================\n";
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
