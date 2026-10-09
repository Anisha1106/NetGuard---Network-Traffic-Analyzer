#pragma once

#include "netguard/core/types.hpp"
#include "netguard/core/packet.hpp"
#include <string>
#include <cstdint>
#include <functional>

namespace netguard {

struct FlowKey {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port{0};
    uint16_t dst_port{0};
    Protocol protocol{Protocol::UNKNOWN};

    bool operator==(const FlowKey& other) const {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port &&
               protocol == other.protocol;
    }

    std::string to_string() const {
        return src_ip + ":" + std::to_string(src_port) + " -> " +
               dst_ip + ":" + std::to_string(dst_port) + " [" +
               std::string(protocol_to_string(protocol)) + "]";
    }
};

struct FlowKeyHash {
    std::size_t operator()(const FlowKey& k) const noexcept {
        std::size_t h1 = std::hash<std::string>{}(k.src_ip);
        std::size_t h2 = std::hash<std::string>{}(k.dst_ip);
        std::size_t h3 = std::hash<uint32_t>{}((static_cast<uint32_t>(k.src_port) << 16) | k.dst_port);
        std::size_t h4 = std::hash<uint8_t>{}(static_cast<uint8_t>(k.protocol));
        return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3);
    }
};

struct FlowMetrics {
    FlowKey key;
    uint64_t packet_count{0};
    uint64_t byte_count{0};
    uint64_t first_seen_us{0};
    uint64_t last_seen_us{0};
    uint32_t syn_count{0};
    uint32_t fin_count{0};
    uint32_t rst_count{0};

    void update(const ParsedPacket& pkt) {
        if (packet_count == 0) {
            first_seen_us = pkt.timestamp_us;
        }
        last_seen_us = pkt.timestamp_us;
        packet_count++;
        byte_count += pkt.ip_total_len > 0 ? pkt.ip_total_len : pkt.payload_len;

        if (pkt.protocol == Protocol::TCP) {
            if (pkt.tcp_flags.syn) syn_count++;
            if (pkt.tcp_flags.fin) fin_count++;
            if (pkt.tcp_flags.rst) rst_count++;
        }
    }

    double duration_seconds() const {
        if (last_seen_us <= first_seen_us) return 0.0;
        return (last_seen_us - first_seen_us) / 1000000.0;
    }

    double packets_per_second() const {
        double dur = duration_seconds();
        return dur > 0.0 ? packet_count / dur : packet_count;
    }

    double bytes_per_second() const {
        double dur = duration_seconds();
        return dur > 0.0 ? byte_count / dur : byte_count;
    }
};

} // namespace netguard
