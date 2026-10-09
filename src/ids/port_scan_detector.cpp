#include "netguard/ids/port_scan_detector.hpp"
#include <algorithm>
#include <sstream>

namespace netguard {

PortScanDetector::PortScanDetector(const RuleConfig& config) : config_(config) {}

void PortScanDetector::inspect(const ParsedPacket& pkt, std::vector<Alert>& alerts) {
    if (!config_.enable_port_scan_detection || !pkt.is_valid || pkt.src_ip.empty()) {
        return;
    }

    if (pkt.protocol != Protocol::TCP && pkt.protocol != Protocol::UDP) {
        return;
    }

    std::unique_lock lock(mutex_);
    auto& rec = records_[pkt.src_ip];

    // Purge outdated target ports outside window
    uint64_t window_start = (pkt.timestamp_us > config_.port_scan_window_us)
                            ? (pkt.timestamp_us - config_.port_scan_window_us) : 0;

    rec.targets.erase(
        std::remove_if(rec.targets.begin(), rec.targets.end(), [window_start](const TargetPort& tp) {
            return tp.timestamp_us < window_start;
        }),
        rec.targets.end()
    );

    // Add new port target
    rec.targets.push_back({pkt.dst_ip, pkt.dst_port, pkt.timestamp_us});

    // Count unique (dst_ip, dst_port) combinations
    std::unordered_set<uint32_t> unique_ports;
    for (const auto& tp : rec.targets) {
        unique_ports.insert(tp.dst_port);
    }

    if (unique_ports.size() >= config_.port_scan_threshold_ports) {
        if (!rec.alert_fired || (pkt.timestamp_us - rec.last_alert_time_us) > config_.port_scan_window_us) {
            rec.alert_fired = true;
            rec.last_alert_time_us = pkt.timestamp_us;

            Alert alert;
            alert.alert_id = ++alert_counter_;
            alert.timestamp_us = pkt.timestamp_us;
            alert.severity = AlertSeverity::HIGH;
            alert.type = AlertType::PORT_SCAN;
            alert.rule_name = "Port Scan Threshold Exceeded";
            alert.src_ip = pkt.src_ip;
            alert.dst_ip = pkt.dst_ip;
            alert.dst_port = pkt.dst_port;
            alert.protocol = pkt.protocol;
            
            std::ostringstream ss;
            ss << "Source IP " << pkt.src_ip << " scanned " << unique_ports.size()
               << " distinct ports within " << (config_.port_scan_window_us / 1000000.0) << " seconds.";
            alert.description = ss.str();
            alert.metric_value = static_cast<double>(unique_ports.size());
            alert.threshold_value = static_cast<double>(config_.port_scan_threshold_ports);

            alerts.push_back(std::move(alert));
        }
    }
}

void PortScanDetector::periodic_check(uint64_t current_time_us, std::vector<Alert>& alerts) {
    (void)alerts;
    std::unique_lock lock(mutex_);
    for (auto it = records_.begin(); it != records_.end(); ) {
        uint64_t window_start = (current_time_us > config_.port_scan_window_us)
                                ? (current_time_us - config_.port_scan_window_us) : 0;
        auto& targets = it->second.targets;
        targets.erase(
            std::remove_if(targets.begin(), targets.end(), [window_start](const TargetPort& tp) {
                return tp.timestamp_us < window_start;
            }),
            targets.end()
        );
        if (targets.empty()) {
            it = records_.erase(it);
        } else {
            ++it;
        }
    }
}

void PortScanDetector::reset() {
    std::unique_lock lock(mutex_);
    records_.clear();
}

} // namespace netguard
