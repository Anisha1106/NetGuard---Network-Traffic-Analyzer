#pragma once

#include <cstdint>
#include <arpa/inet.h>

namespace netguard {

#pragma pack(push, 1)

struct RawEthernetHeader {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ethertype;
};

struct RawIPv4Header {
    uint8_t  ver_ihl;       // Version (4 bits) + Internet Header Length (4 bits)
    uint8_t  tos;           // Type of Service / DSCP+ECN
    uint16_t total_length;  // Total Length
    uint16_t id;            // Identification
    uint16_t flags_fragment;// Flags (3 bits) + Fragment Offset (13 bits)
    uint8_t  ttl;           // Time to Live
    uint8_t  protocol;      // Transport Protocol
    uint16_t checksum;     // Header Checksum
    uint32_t src_ip;        // Source IP Address (Network Byte Order)
    uint32_t dst_ip;        // Destination IP Address (Network Byte Order)

    uint8_t version() const { return (ver_ihl >> 4) & 0x0F; }
    uint8_t header_length_bytes() const { return (ver_ihl & 0x0F) * 4; }
};

struct RawIPv6Header {
    uint32_t v_tc_fl;       // Version (4), Traffic Class (8), Flow Label (20)
    uint16_t payload_length;
    uint8_t  next_header;
    uint8_t  hop_limit;
    uint8_t  src_ip[16];
    uint8_t  dst_ip[16];
};

struct RawTCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  data_offset_reserved; // Data Offset (4 bits) + Reserved (4 bits)
    uint8_t  flags;                // TCP Flags (8 bits)
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;

    uint8_t header_length_bytes() const { return ((data_offset_reserved >> 4) & 0x0F) * 4; }
};

struct RawUDPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

struct RawPCAPHeader {
    uint32_t magic_number;   // 0xa1b2c3d4 or 0xa1b23c4d (nanosec)
    uint16_t version_major;  // 2
    uint16_t version_minor;  // 4
    int32_t  thiszone;       // gmt to local correction
    uint32_t sigfigs;        // accuracy of timestamps
    uint32_t snaplen;        // max length of captured packets
    uint32_t network;        // data link type (1 = Ethernet DLT_EN10MB)
};

struct RawPCAPRecordHeader {
    uint32_t ts_sec;         // timestamp seconds
    uint32_t ts_usec;        // timestamp microseconds or nanoseconds
    uint32_t incl_len;       // number of octets of packet saved in file
    uint32_t orig_len;       // actual length of packet
};

#pragma pack(pop)

} // namespace netguard
