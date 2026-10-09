#pragma once

#include "netguard/core/packet.hpp"
#include <span>

namespace netguard {

class PacketParser {
public:
    static ParsedPacket parse(const RawPacket& raw);
    static ParsedPacket parse(std::span<const uint8_t> bytes, uint64_t packet_id = 0, uint64_t timestamp_us = 0);

private:
    static bool parse_ethernet(std::span<const uint8_t> bytes, ParsedPacket& pkt, size_t& offset);
    static bool parse_ipv4(std::span<const uint8_t> bytes, ParsedPacket& pkt, size_t& offset);
    static bool parse_ipv6(std::span<const uint8_t> bytes, ParsedPacket& pkt, size_t& offset);
    static bool parse_tcp(std::span<const uint8_t> bytes, ParsedPacket& pkt, size_t& offset);
    static bool parse_udp(std::span<const uint8_t> bytes, ParsedPacket& pkt, size_t& offset);
};

} // namespace netguard
