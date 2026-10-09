#include "netguard/core/types.hpp"
#include "netguard/parser/headers.hpp"
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <arpa/inet.h>

using namespace netguard;

class PCAPWriter {
public:
    explicit PCAPWriter(const std::string& filepath) : file_(filepath, std::ios::binary) {
        RawPCAPHeader hdr{};
        hdr.magic_number = 0xa1b2c3d4;
        hdr.version_major = 2;
        hdr.version_minor = 4;
        hdr.thiszone = 0;
        hdr.sigfigs = 0;
        hdr.snaplen = 65535;
        hdr.network = 1; // Ethernet
        file_.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));
    }

    void write_packet(const std::vector<uint8_t>& payload, uint32_t ts_sec, uint32_t ts_usec) {
        RawPCAPRecordHeader rec{};
        rec.ts_sec = ts_sec;
        rec.ts_usec = ts_usec;
        rec.incl_len = static_cast<uint32_t>(payload.size());
        rec.orig_len = static_cast<uint32_t>(payload.size());

        file_.write(reinterpret_cast<const char*>(&rec), sizeof(rec));
        file_.write(reinterpret_cast<const char*>(payload.data()), payload.size());
    }

private:
    std::ofstream file_;
};

std::vector<uint8_t> create_ip_tcp_packet(const std::string& src_ip_str, uint16_t src_port,
                                          const std::string& dst_ip_str, uint16_t dst_port,
                                          uint8_t tcp_flags_byte, const std::string& payload_data = "") {
    std::vector<uint8_t> pkt(sizeof(RawEthernetHeader) + sizeof(RawIPv4Header) + sizeof(RawTCPHeader) + payload_data.size());

    // Ethernet Header
    auto* eth = reinterpret_cast<RawEthernetHeader*>(pkt.data());
    eth->src_mac[0] = 0x00; eth->src_mac[1] = 0x11; eth->src_mac[2] = 0x22;
    eth->src_mac[3] = 0x33; eth->src_mac[4] = 0x44; eth->src_mac[5] = 0x55;
    eth->dst_mac[0] = 0x66; eth->dst_mac[1] = 0x77; eth->dst_mac[2] = 0x88;
    eth->dst_mac[3] = 0x99; eth->dst_mac[4] = 0xAA; eth->dst_mac[5] = 0xBB;
    eth->ethertype = htons(static_cast<uint16_t>(EtherType::IPv4));

    // IPv4 Header
    auto* ip = reinterpret_cast<RawIPv4Header*>(pkt.data() + sizeof(RawEthernetHeader));
    ip->ver_ihl = 0x45; // Version 4, IHL 5 (20 bytes)
    ip->tos = 0;
    uint16_t total_len = sizeof(RawIPv4Header) + sizeof(RawTCPHeader) + payload_data.size();
    ip->total_length = htons(total_len);
    ip->id = htons(12345);
    ip->flags_fragment = 0;
    ip->ttl = 64;
    ip->protocol = static_cast<uint8_t>(Protocol::TCP);
    ip->checksum = 0;
    inet_pton(AF_INET, src_ip_str.c_str(), &ip->src_ip);
    inet_pton(AF_INET, dst_ip_str.c_str(), &ip->dst_ip);

    // TCP Header
    auto* tcp = reinterpret_cast<RawTCPHeader*>(pkt.data() + sizeof(RawEthernetHeader) + sizeof(RawIPv4Header));
    tcp->src_port = htons(src_port);
    tcp->dst_port = htons(dst_port);
    tcp->seq_num = htonl(1000);
    tcp->ack_num = htonl(0);
    tcp->data_offset_reserved = 0x50; // 5 dwords (20 bytes)
    tcp->flags = tcp_flags_byte;
    tcp->window_size = htons(64240);
    tcp->checksum = 0;
    tcp->urgent_pointer = 0;

    if (!payload_data.empty()) {
        std::memcpy(pkt.data() + sizeof(RawEthernetHeader) + sizeof(RawIPv4Header) + sizeof(RawTCPHeader),
                    payload_data.data(), payload_data.size());
    }

    return pkt;
}

int main(int argc, char** argv) {
    std::string output_file = "sample_attack.pcap";
    if (argc > 1) {
        output_file = argv[1];
    }

    std::cout << "Generating sample attack PCAP file: " << output_file << "...\n";
    PCAPWriter writer(output_file);

    uint32_t ts_sec = 1700000000;
    uint32_t ts_usec = 1000;

    // 1. Normal HTTP traffic
    std::cout << "  - Adding normal HTTP traffic...\n";
    for (int i = 0; i < 10; ++i) {
        auto pkt = create_ip_tcp_packet("192.168.1.10", 50000 + i, "93.184.216.34", 80, 0x02, "GET /index.html HTTP/1.1\r\n\r\n");
        writer.write_packet(pkt, ts_sec, ts_usec += 10000);
    }

    // 2. Port Scan Attack from 192.168.1.50 scanning 25 ports
    std::cout << "  - Adding SYN Port Scan attack from 192.168.1.50...\n";
    for (uint16_t port = 20; port <= 45; ++port) {
        auto pkt = create_ip_tcp_packet("192.168.1.50", 40000 + port, "192.168.1.1", port, 0x02); // SYN flag
        writer.write_packet(pkt, ts_sec, ts_usec += 5000);
    }

    // 3. SYN Flood Attack from 10.0.0.66
    std::cout << "  - Adding SYN Flood attack from 10.0.0.66...\n";
    for (int i = 0; i < 60; ++i) {
        auto pkt = create_ip_tcp_packet("10.0.0.66", 30000 + i, "192.168.1.1", 443, 0x02); // SYN
        writer.write_packet(pkt, ts_sec, ts_usec += 1000);
    }

    // 4. TCP Xmas Scan from 192.168.1.77
    std::cout << "  - Adding TCP Xmas Scan from 192.168.1.77...\n";
    {
        auto pkt = create_ip_tcp_packet("192.168.1.77", 44444, "192.168.1.1", 80, 0x29); // FIN+PSH+URG
        writer.write_packet(pkt, ts_sec, ts_usec += 10000);
    }

    // 5. TCP Null Scan from 192.168.1.88
    std::cout << "  - Adding TCP Null Scan from 192.168.1.88...\n";
    {
        auto pkt = create_ip_tcp_packet("192.168.1.88", 55555, "192.168.1.1", 80, 0x00); // No flags
        writer.write_packet(pkt, ts_sec, ts_usec += 10000);
    }

    // 6. Suspicious Port connection to 31337 and 4444
    std::cout << "  - Adding traffic to suspicious backdoor ports (31337, 4444)...\n";
    {
        auto pkt1 = create_ip_tcp_packet("192.168.1.99", 51234, "192.168.1.1", 31337, 0x18, "Backdoor Payload");
        writer.write_packet(pkt1, ts_sec, ts_usec += 10000);

        auto pkt2 = create_ip_tcp_packet("192.168.1.99", 51235, "192.168.1.1", 4444, 0x18, "Shell Code");
        writer.write_packet(pkt2, ts_sec, ts_usec += 10000);
    }

    std::cout << "[✓] Successfully generated " << output_file << "!\n";
    return 0;
}
