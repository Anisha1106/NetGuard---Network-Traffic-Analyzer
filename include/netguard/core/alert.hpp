#pragma once

#include "netguard/core/types.hpp"
#include <string>
#include <cstdint>
#include <string_view>

namespace netguard {

enum class AlertSeverity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

std::string_view severity_to_string(AlertSeverity sev);

enum class AlertType {
    PORT_SCAN,
    BRUTE_FORCE_ATTEMPT,
    TRAFFIC_SPIKE,
    SUSPICIOUS_PORT,
    XMAS_SCAN,
    NULL_SCAN,
    DNS_ANOMALY,
    MALFORMED_PACKET
};

std::string_view alert_type_to_string(AlertType type);

struct Alert {
    uint64_t alert_id{0};
    uint64_t timestamp_us{0};
    AlertSeverity severity{AlertSeverity::MEDIUM};
    AlertType type{AlertType::PORT_SCAN};
    std::string rule_name;
    std::string src_ip;
    std::string dst_ip;
    uint16_t dst_port{0};
    Protocol protocol{Protocol::UNKNOWN};
    std::string description;
    double metric_value{0.0};
    double threshold_value{0.0};

    std::string to_formatted_string() const;
};

} // namespace netguard
