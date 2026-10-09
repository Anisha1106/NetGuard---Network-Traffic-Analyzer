#include "netguard/core/alert.hpp"
#include <sstream>
#include <iomanip>

namespace netguard {

std::string_view severity_to_string(AlertSeverity sev) {
    switch (sev) {
        case AlertSeverity::INFO:     return "INFO";
        case AlertSeverity::LOW:      return "LOW";
        case AlertSeverity::MEDIUM:   return "MEDIUM";
        case AlertSeverity::HIGH:     return "HIGH";
        case AlertSeverity::CRITICAL: return "CRITICAL";
        default:                      return "UNKNOWN";
    }
}

std::string_view alert_type_to_string(AlertType type) {
    switch (type) {
        case AlertType::PORT_SCAN:            return "PORT_SCAN";
        case AlertType::BRUTE_FORCE_ATTEMPT:  return "BRUTE_FORCE_ATTEMPT";
        case AlertType::TRAFFIC_SPIKE:        return "TRAFFIC_SPIKE";
        case AlertType::SUSPICIOUS_PORT:      return "SUSPICIOUS_PORT";
        case AlertType::XMAS_SCAN:            return "XMAS_SCAN";
        case AlertType::NULL_SCAN:            return "NULL_SCAN";
        case AlertType::DNS_ANOMALY:          return "DNS_ANOMALY";
        case AlertType::MALFORMED_PACKET:     return "MALFORMED_PACKET";
        default:                              return "UNKNOWN";
    }
}

std::string Alert::to_formatted_string() const {
    std::ostringstream ss;
    ss << "[" << severity_to_string(severity) << "] "
       << alert_type_to_string(type) << " | Rule: " << rule_name
       << " | Src: " << src_ip << " -> Dst: " << dst_ip;
    if (dst_port > 0) {
        ss << ":" << dst_port;
    }
    ss << " | " << description;
    if (threshold_value > 0.0) {
        ss << " (Val: " << metric_value << " / Thresh: " << threshold_value << ")";
    }
    return ss.str();
}

} // namespace netguard
