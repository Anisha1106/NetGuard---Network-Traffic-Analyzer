#include "netguard/ids/anomaly_detector.hpp"
#include <sstream>

namespace netguard {

AnomalyDetector::AnomalyDetector(const RuleConfig& config) : config_(config) {}

void AnomalyDetector::inspect(const ParsedPacket& pkt, std::vector<Alert>& alerts) {
    if (!config_.enable_anomaly_detection) {
        return;
    }

    std::lock_guard lock(mutex_);

    // Check for malformed packets
    if (!pkt.is_valid) {
        Alert alert;
        alert.alert_id = ++alert_counter_;
        alert.timestamp_us = pkt.timestamp_us;
        alert.severity = AlertSeverity::MEDIUM;
        alert.type = AlertType::MALFORMED_PACKET;
        alert.rule_name = "Malformed Packet Header";
        alert.src_ip = pkt.src_ip;
        alert.dst_ip = pkt.dst_ip;
        alert.description = "Packet failed parsing: " + pkt.error_message;
        alerts.push_back(std::move(alert));
        return;
    }

    if (pkt.protocol == Protocol::TCP) {
        // Xmas Scan Detection
        if (config_.detect_xmas_scans && pkt.tcp_flags.is_xmas()) {
            Alert alert;
            alert.alert_id = ++alert_counter_;
            alert.timestamp_us = pkt.timestamp_us;
            alert.severity = AlertSeverity::HIGH;
            alert.type = AlertType::XMAS_SCAN;
            alert.rule_name = "TCP Xmas Stealth Scan";
            alert.src_ip = pkt.src_ip;
            alert.dst_ip = pkt.dst_ip;
            alert.dst_port = pkt.dst_port;
            alert.protocol = Protocol::TCP;
            alert.description = "Stealth Xmas scan detected (FIN, PSH, URG flags set)";
            alerts.push_back(std::move(alert));
        }

        // Null Scan Detection
        if (config_.detect_null_scans && pkt.tcp_flags.is_null()) {
            Alert alert;
            alert.alert_id = ++alert_counter_;
            alert.timestamp_us = pkt.timestamp_us;
            alert.severity = AlertSeverity::HIGH;
            alert.type = AlertType::NULL_SCAN;
            alert.rule_name = "TCP Null Stealth Scan";
            alert.src_ip = pkt.src_ip;
            alert.dst_ip = pkt.dst_ip;
            alert.dst_port = pkt.dst_port;
            alert.protocol = Protocol::TCP;
            alert.description = "Stealth Null scan detected (No TCP flags set)";
            alerts.push_back(std::move(alert));
        }
    }

    // Suspicious Port Check
    if (config_.detect_suspicious_ports) {
        if (config_.suspicious_ports.count(pkt.dst_port) > 0) {
            Alert alert;
            alert.alert_id = ++alert_counter_;
            alert.timestamp_us = pkt.timestamp_us;
            alert.severity = AlertSeverity::MEDIUM;
            alert.type = AlertType::SUSPICIOUS_PORT;
            alert.rule_name = "Suspicious Destination Port Contact";
            alert.src_ip = pkt.src_ip;
            alert.dst_ip = pkt.dst_ip;
            alert.dst_port = pkt.dst_port;
            alert.protocol = pkt.protocol;
            
            std::ostringstream ss;
            ss << "Traffic targeting suspicious / high-risk port " << pkt.dst_port;
            alert.description = ss.str();
            alert.metric_value = static_cast<double>(pkt.dst_port);

            alerts.push_back(std::move(alert));
        }
    }
}

void AnomalyDetector::periodic_check(uint64_t current_time_us, std::vector<Alert>& alerts) {
    (void)current_time_us;
    (void)alerts;
}

void AnomalyDetector::reset() {
    std::lock_guard lock(mutex_);
}

} // namespace netguard
