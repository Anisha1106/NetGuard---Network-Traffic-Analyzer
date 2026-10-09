#pragma once

#include <cstdint>
#include <string>
#include <chrono>
#include <string_view>
#include <iostream>

namespace netguard {

using Timestamp = std::chrono::time_point<std::chrono::high_resolution_clock>;
using Microseconds = std::chrono::microseconds;

enum class Protocol : uint8_t {
    UNKNOWN = 0,
    HOPOPT  = 0,
    ICMP    = 1,
    IGMP    = 2,
    TCP     = 6,
    UDP     = 17,
    IPv6_Route = 43,
    IPv6_Frag  = 44,
    GRE     = 47,
    ESP     = 50,
    AH      = 51,
    ICMPv6  = 58,
    RAW     = 255
};

std::string_view protocol_to_string(Protocol proto);

enum class EtherType : uint16_t {
    IPv4 = 0x0800,
    ARP  = 0x0806,
    VLAN = 0x8100,
    IPv6 = 0x86DD,
    UNKNOWN = 0x0000
};

std::string_view ethertype_to_string(EtherType type);

struct TCPFlags {
    bool fin{false};
    bool syn{false};
    bool rst{false};
    bool psh{false};
    bool ack{false};
    bool urg{false};
    bool ece{false};
    bool cwr{false};

    uint8_t to_byte() const {
        return (cwr << 7) | (ece << 6) | (urg << 5) | (ack << 4) |
               (psh << 3) | (rst << 2) | (syn << 1) | (fin << 0);
    }

    static TCPFlags from_byte(uint8_t val) {
        TCPFlags f;
        f.fin = (val & 0x01) != 0;
        f.syn = (val & 0x02) != 0;
        f.rst = (val & 0x04) != 0;
        f.psh = (val & 0x08) != 0;
        f.ack = (val & 0x10) != 0;
        f.urg = (val & 0x20) != 0;
        f.ece = (val & 0x40) != 0;
        f.cwr = (val & 0x80) != 0;
        return f;
    }

    bool is_xmas() const { return fin && psh && urg; }
    bool is_null() const { return !fin && !syn && !rst && !psh && !ack && !urg; }
    bool is_syn_only() const { return syn && !ack && !rst && !fin; }
};

struct MACAddress {
    uint8_t bytes[6]{0};
    std::string to_string() const;
};

} // namespace netguard
