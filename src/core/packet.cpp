#include "netguard/core/packet.hpp"
#include <sstream>

namespace netguard {

std::string ParsedPacket::summary() const {
    std::ostringstream ss;
    ss << "#" << packet_id << " [" << ethertype_to_string(ethertype) << "]";
    if (!src_ip.empty()) {
        ss << " " << src_ip;
        if (src_port > 0) ss << ":" << src_port;
        ss << " -> " << dst_ip;
        if (dst_port > 0) ss << ":" << dst_port;
        ss << " [" << protocol_to_string(protocol) << "]";
    }
    if (protocol == Protocol::TCP) {
        ss << " Flags:[";
        if (tcp_flags.syn) ss << "SYN ";
        if (tcp_flags.ack) ss << "ACK ";
        if (tcp_flags.fin) ss << "FIN ";
        if (tcp_flags.rst) ss << "RST ";
        if (tcp_flags.psh) ss << "PSH ";
        if (tcp_flags.urg) ss << "URG ";
        ss << "]";
    }
    ss << " len=" << payload_len;
    return ss.str();
}

} // namespace netguard
