#include "netguard/parser/pcap_reader.hpp"
#include <iostream>
#include <stdexcept>

#if defined(__linux__)
#include <byteswap.h>
#elif defined(__APPLE__) || defined(__FreeBSD__)
#include <libkern/OSByteOrder.h>
#define bswap_16(x) OSSwapInt16(x)
#define bswap_32(x) OSSwapInt32(x)
#else
static inline uint16_t bswap_16(uint16_t x) {
    return (x >> 8) | (x << 8);
}
static inline uint32_t bswap_32(uint32_t x) {
    return ((x >> 24) & 0xff) | ((x >> 8) & 0xff00) |
           ((x << 8) & 0xff0000) | ((x << 24) & 0xff000000);
}
#endif

namespace netguard {

PCAPReader::PCAPReader(std::string filepath) : filepath_(std::move(filepath)) {}

PCAPReader::~PCAPReader() {
    close();
}

uint32_t PCAPReader::swap32(uint32_t val) const {
    return is_byteswapped_ ? bswap_32(val) : val;
}

uint16_t PCAPReader::swap16(uint16_t val) const {
    return is_byteswapped_ ? bswap_16(val) : val;
}

bool PCAPReader::open() {
    file_.open(filepath_, std::ios::binary);
    if (!file_.is_open()) {
        return false;
    }

    file_.read(reinterpret_cast<char*>(&global_header_), sizeof(RawPCAPHeader));
    if (file_.gcount() < static_cast<std::streamsize>(sizeof(RawPCAPHeader))) {
        close();
        return false;
    }

    if (global_header_.magic_number == 0xa1b2c3d4) {
        is_byteswapped_ = false;
        is_nanosecond_ = false;
    } else if (global_header_.magic_number == 0xa1b23c4d) {
        is_byteswapped_ = false;
        is_nanosecond_ = true;
    } else if (global_header_.magic_number == 0xd4c3b2a1) {
        is_byteswapped_ = true;
        is_nanosecond_ = false;
    } else if (global_header_.magic_number == 0x4dc3b2a1) {
        is_byteswapped_ = true;
        is_nanosecond_ = true;
    } else {
        close();
        return false; // Unknown PCAP magic number
    }

    global_header_.snaplen = swap32(global_header_.snaplen);
    global_header_.network = swap32(global_header_.network);

    return true;
}

void PCAPReader::close() {
    if (file_.is_open()) {
        file_.close();
    }
}

bool PCAPReader::is_open() const {
    return file_.is_open();
}

bool PCAPReader::read_next_packet(RawPacket& packet) {
    if (!file_.is_open() || file_.eof()) {
        return false;
    }

    RawPCAPRecordHeader pkt_hdr{};
    file_.read(reinterpret_cast<char*>(&pkt_hdr), sizeof(RawPCAPRecordHeader));
    if (file_.gcount() < static_cast<std::streamsize>(sizeof(RawPCAPRecordHeader))) {
        return false;
    }

    uint32_t sec = swap32(pkt_hdr.ts_sec);
    uint32_t usec = swap32(pkt_hdr.ts_usec);
    uint32_t caplen = swap32(pkt_hdr.incl_len);
    uint32_t origlen = swap32(pkt_hdr.orig_len);

    if (caplen > 65535) {
        return false; // Corrupted packet header length safeguard
    }

    packet.packet_id = ++packet_counter_;
    packet.timestamp_us = static_cast<uint64_t>(sec) * 1000000ULL + (is_nanosecond_ ? (usec / 1000ULL) : usec);
    packet.captured_len = caplen;
    packet.original_len = origlen;

    packet.payload.resize(caplen);
    file_.read(reinterpret_cast<char*>(packet.payload.data()), caplen);
    if (file_.gcount() < static_cast<std::streamsize>(caplen)) {
        return false;
    }

    return true;
}

std::vector<RawPacket> PCAPReader::read_all() {
    std::vector<RawPacket> packets;
    RawPacket pkt;
    while (read_next_packet(pkt)) {
        packets.push_back(std::move(pkt));
    }
    return packets;
}

} // namespace netguard
