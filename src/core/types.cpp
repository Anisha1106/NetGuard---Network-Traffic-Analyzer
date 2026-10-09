#include "netguard/core/types.hpp"
#include <cstdio>
#include <sstream>
#include <iomanip>

namespace netguard {

std::string_view protocol_to_string(Protocol proto) {
    switch (proto) {
        case Protocol::ICMP:   return "ICMP";
        case Protocol::IGMP:   return "IGMP";
        case Protocol::TCP:    return "TCP";
        case Protocol::UDP:    return "UDP";
        case Protocol::ICMPv6: return "ICMPv6";
        case Protocol::GRE:    return "GRE";
        case Protocol::ESP:    return "ESP";
        case Protocol::AH:     return "AH";
        default:               return "UNKNOWN";
    }
}

std::string_view ethertype_to_string(EtherType type) {
    switch (type) {
        case EtherType::IPv4: return "IPv4";
        case EtherType::IPv6: return "IPv6";
        case EtherType::ARP:  return "ARP";
        case EtherType::VLAN: return "VLAN";
        default:              return "UNKNOWN";
    }
}

std::string MACAddress::to_string() const {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                  bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
    return std::string(buf);
}

} // namespace netguard
