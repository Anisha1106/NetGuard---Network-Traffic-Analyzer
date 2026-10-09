#include "netguard/parser/packet_parser.hpp"
#include "netguard/parser/headers.hpp"
#include <cstring>
#include <arpa/inet.h>

namespace netguard {

ParsedPacket PacketParser::parse(const RawPacket& raw) {
    return parse(std::span<const uint8_t>(raw.payload.data(), raw.payload.size()), raw.packet_id, raw.timestamp_us);
}

ParsedPacket PacketParser::parse(std::span<const uint8_t> bytes, uint64_t packet_id, uint64_t timestamp_us) {
    ParsedPacket pkt;
    pkt.packet_id = packet_id;
    pkt.timestamp_us = timestamp_us;

    if (bytes.size() < sizeof(RawEthernetHeader)) {
        pkt.is_valid = false;
        pkt.error_message = "Frame shorter than Ethernet header";
        return pkt;
    }

    size_t offset = 0;
    if (!parse_ethernet(bytes, pkt, offset)) {
        return pkt;
    }

    if (pkt.ethertype == EtherType::IPv4) {
        if (!parse_ipv4(bytes, pkt, offset)) {
            return pkt;
        }
    } else if (pkt.ethertype == EtherType::IPv6) {
        if (!parse_ipv6(bytes, pkt, offset)) {
            return pkt;
        }
    } else {
        // Non-IP frame (e.g. ARP, VLAN)
        pkt.payload_offset = offset;
        pkt.payload_len = (bytes.size() > offset) ? (bytes.size() - offset) : 0;
        return pkt;
    }

    // Transport layer parsing
    if (pkt.protocol == Protocol::TCP) {
        parse_tcp(bytes, pkt, offset);
    } else if (pkt.protocol == Protocol::UDP) {
        parse_udp(bytes, pkt, offset);
    } else {
        pkt.payload_offset = offset;
        pkt.payload_len = (bytes.size() > offset) ? (bytes.size() - offset) : 0;
    }

    return pkt;
}

bool PacketParser::parse_ethernet(std::span<const uint8_t> bytes, ParsedPacket& pkt, size_t& offset) {
    if (bytes.size() < sizeof(RawEthernetHeader)) {
        pkt.is_valid = false;
        pkt.error_message = "Truncated Ethernet header";
        return false;
    }

    const auto* eth = reinterpret_cast<const RawEthernetHeader*>(bytes.data());
    std::memcpy(pkt.dst_mac.bytes, eth->dst_mac, 6);
    std::memcpy(pkt.src_mac.bytes, eth->src_mac, 6);
    pkt.ethertype = static_cast<EtherType>(ntohs(eth->ethertype));

    offset += sizeof(RawEthernetHeader);

    // Support VLAN Tagging (0x8100)
    if (pkt.ethertype == EtherType::VLAN) {
        if (bytes.size() < offset + 4) {
            pkt.is_valid = false;
            pkt.error_message = "Truncated VLAN header";
            return false;
        }
        uint16_t encapsulated_proto = ntohs(*reinterpret_cast<const uint16_t*>(bytes.data() + offset + 2));
        pkt.ethertype = static_cast<EtherType>(encapsulated_proto);
        offset += 4;
    }

    return true;
}

bool PacketParser::parse_ipv4(std::span<const uint8_t> bytes, ParsedPacket& pkt, size_t& offset) {
    if (bytes.size() < offset + sizeof(RawIPv4Header)) {
        pkt.is_valid = false;
        pkt.error_message = "Truncated IPv4 header";
        return false;
    }

    const auto* ip = reinterpret_cast<const RawIPv4Header*>(bytes.data() + offset);
    uint8_t ihl_bytes = ip->header_length_bytes();
    if (ihl_bytes < 20 || bytes.size() < offset + ihl_bytes) {
        pkt.is_valid = false;
        pkt.error_message = "Invalid IPv4 header length (IHL)";
        return false;
    }

    pkt.is_ipv6 = false;
    pkt.ttl = ip->ttl;
    pkt.ip_id = ntohs(ip->id);
    pkt.ip_total_len = ntohs(ip->total_length);
    pkt.protocol = static_cast<Protocol>(ip->protocol);

    char src_buf[INET_ADDRSTRLEN]{0};
    char dst_buf[INET_ADDRSTRLEN]{0};
    inet_ntop(AF_INET, &(ip->src_ip), src_buf, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->dst_ip), dst_buf, INET_ADDRSTRLEN);

    pkt.src_ip = src_buf;
    pkt.dst_ip = dst_buf;

    offset += ihl_bytes;
    return true;
}

bool PacketParser::parse_ipv6(std::span<const uint8_t> bytes, ParsedPacket& pkt, size_t& offset) {
    if (bytes.size() < offset + sizeof(RawIPv6Header)) {
        pkt.is_valid = false;
        pkt.error_message = "Truncated IPv6 header";
        return false;
    }

    const auto* ip6 = reinterpret_cast<const RawIPv6Header*>(bytes.data() + offset);
    pkt.is_ipv6 = true;
    pkt.ttl = ip6->hop_limit;
    pkt.ip_total_len = ntohs(ip6->payload_length) + sizeof(RawIPv6Header);
    pkt.protocol = static_cast<Protocol>(ip6->next_header);

    char src_buf[INET6_ADDRSTRLEN]{0};
    char dst_buf[INET6_ADDRSTRLEN]{0};
    inet_ntop(AF_INET6, ip6->src_ip, src_buf, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, ip6->dst_ip, dst_buf, INET6_ADDRSTRLEN);

    pkt.src_ip = src_buf;
    pkt.dst_ip = dst_buf;

    offset += sizeof(RawIPv6Header);
    return true;
}

bool PacketParser::parse_tcp(std::span<const uint8_t> bytes, ParsedPacket& pkt, size_t& offset) {
    if (bytes.size() < offset + sizeof(RawTCPHeader)) {
        pkt.is_valid = false;
        pkt.error_message = "Truncated TCP header";
        return false;
    }

    const auto* tcp = reinterpret_cast<const RawTCPHeader*>(bytes.data() + offset);
    uint8_t tcp_len = tcp->header_length_bytes();
    if (tcp_len < 20 || bytes.size() < offset + tcp_len) {
        pkt.is_valid = false;
        pkt.error_message = "Invalid TCP data offset";
        return false;
    }

    pkt.src_port = ntohs(tcp->src_port);
    pkt.dst_port = ntohs(tcp->dst_port);
    pkt.seq_num = ntohl(tcp->seq_num);
    pkt.ack_num = ntohl(tcp->ack_num);
    pkt.window_size = ntohs(tcp->window_size);
    pkt.tcp_flags = TCPFlags::from_byte(tcp->flags);

    offset += tcp_len;
    pkt.payload_offset = offset;
    pkt.payload_len = (bytes.size() > offset) ? (bytes.size() - offset) : 0;
    return true;
}

bool PacketParser::parse_udp(std::span<const uint8_t> bytes, ParsedPacket& pkt, size_t& offset) {
    if (bytes.size() < offset + sizeof(RawUDPHeader)) {
        pkt.is_valid = false;
        pkt.error_message = "Truncated UDP header";
        return false;
    }

    const auto* udp = reinterpret_cast<const RawUDPHeader*>(bytes.data() + offset);
    pkt.src_port = ntohs(udp->src_port);
    pkt.dst_port = ntohs(udp->dst_port);

    offset += sizeof(RawUDPHeader);
    pkt.payload_offset = offset;
    pkt.payload_len = (bytes.size() > offset) ? (bytes.size() - offset) : 0;
    return true;
}

} // namespace netguard
