#pragma once

#include "netguard/core/types.hpp"
#include <span>
#include <vector>
#include <string>
#include <cstdint>

namespace netguard {

struct RawPacket {
    uint64_t packet_id{0};
    uint64_t timestamp_us{0}; // Microseconds since epoch or PCAP capture time
    uint32_t captured_len{0};
    uint32_t original_len{0};
    std::vector<uint8_t> payload;
};

struct ParsedPacket {
    uint64_t packet_id{0};
    uint64_t timestamp_us{0};
    
    // Data Link Layer
    MACAddress src_mac;
    MACAddress dst_mac;
    EtherType ethertype{EtherType::UNKNOWN};

    // Network Layer
    std::string src_ip;
    std::string dst_ip;
    Protocol protocol{Protocol::UNKNOWN};
    uint8_t ttl{0};
    uint16_t ip_id{0};
    uint16_t ip_total_len{0};
    bool is_ipv6{false};

    // Transport Layer
    uint16_t src_port{0};
    uint16_t dst_port{0};
    TCPFlags tcp_flags;
    uint32_t seq_num{0};
    uint32_t ack_num{0};
    uint16_t window_size{0};

    // Payload metadata
    size_t payload_offset{0};
    size_t payload_len{0};

    // Parse status
    bool is_valid{true};
    std::string error_message;

    std::string summary() const;
};

} // namespace netguard
