#include <gtest/gtest.h>
#include "netguard/parser/packet_parser.hpp"
#include "netguard/parser/headers.hpp"
#include <arpa/inet.h>
#include <vector>
#include <cstring>

using namespace netguard;

TEST(PacketParserTest, ParseIPv4TCP) {
    std::vector<uint8_t> frame(sizeof(RawEthernetHeader) + sizeof(RawIPv4Header) + sizeof(RawTCPHeader) + 5);

    auto* eth = reinterpret_cast<RawEthernetHeader*>(frame.data());
    eth->ethertype = htons(static_cast<uint16_t>(EtherType::IPv4));

    auto* ip = reinterpret_cast<RawIPv4Header*>(frame.data() + sizeof(RawEthernetHeader));
    ip->ver_ihl = 0x45;
    ip->total_length = htons(sizeof(RawIPv4Header) + sizeof(RawTCPHeader) + 5);
    ip->protocol = static_cast<uint8_t>(Protocol::TCP);
    ip->ttl = 64;
    inet_pton(AF_INET, "192.168.1.10", &ip->src_ip);
    inet_pton(AF_INET, "10.0.0.1", &ip->dst_ip);

    auto* tcp = reinterpret_cast<RawTCPHeader*>(frame.data() + sizeof(RawEthernetHeader) + sizeof(RawIPv4Header));
    tcp->src_port = htons(12345);
    tcp->dst_port = htons(80);
    tcp->data_offset_reserved = 0x50; // 20 bytes
    tcp->flags = 0x02; // SYN flag

    std::memcpy(frame.data() + sizeof(RawEthernetHeader) + sizeof(RawIPv4Header) + sizeof(RawTCPHeader), "HELLO", 5);

    ParsedPacket pkt = PacketParser::parse(frame, 1, 1000);

    EXPECT_TRUE(pkt.is_valid);
    EXPECT_EQ(pkt.src_ip, "192.168.1.10");
    EXPECT_EQ(pkt.dst_ip, "10.0.0.1");
    EXPECT_EQ(pkt.src_port, 12345);
    EXPECT_EQ(pkt.dst_port, 80);
    EXPECT_EQ(pkt.protocol, Protocol::TCP);
    EXPECT_TRUE(pkt.tcp_flags.syn);
    EXPECT_FALSE(pkt.tcp_flags.ack);
    EXPECT_EQ(pkt.payload_len, 5);
}

TEST(PacketParserTest, ParseTruncatedHeader) {
    std::vector<uint8_t> short_frame = {0x00, 0x11, 0x22}; // Only 3 bytes
    ParsedPacket pkt = PacketParser::parse(short_frame, 2, 2000);
    EXPECT_FALSE(pkt.is_valid);
    EXPECT_FALSE(pkt.error_message.empty());
}
