#include "netguard/ids/traffic_spike_detector.hpp"
#include <algorithm>
#include <numeric>
#include <sstream>

namespace netguard {

TrafficSpikeDetector::TrafficSpikeDetector(const RuleConfig& config) : config_(config) {}

void TrafficSpikeDetector::inspect(const ParsedPacket& pkt, std::vector<Alert>& alerts) {
    if (!config_.enable_traffic_spike_detection || !pkt.is_valid || pkt.src_ip.empty()) {
        return;
    }

    size_t pkt_bytes = pkt.ip_total_len > 0 ? pkt.ip_total_len : pkt.payload_len;
    std::unique_lock lock(mutex_);
    auto& node = traffic_[pkt.src_ip];

    uint64_t window_start = (pkt.timestamp_us > config_.traffic_spike_window_us)
                            ? (pkt.timestamp_us - config_.traffic_spike_window_us) : 0;

    node.entries.erase(
        std::remove_if(node.entries.begin(), node.entries.end(), [window_start](const PacketEntry& pe) {
            return pe.timestamp_us < window_start;
        }),
        node.entries.end()
    );

    node.entries.push_back({pkt.timestamp_us, pkt_bytes});

    uint64_t total_bytes = 0;
    for (const auto& pe : node.entries) {
        total_bytes += pe.bytes;
    }

    if (total_bytes >= config_.traffic_spike_bytes_per_sec) {
        if (!node.alert_fired || (pkt.timestamp_us - node.last_alert_time_us) > config_.traffic_spike_window_us) {
            node.alert_fired = true;
            node.last_alert_time_us = pkt.timestamp_us;

            Alert alert;
            alert.alert_id = ++alert_counter_;
            alert.timestamp_us = pkt.timestamp_us;
            alert.severity = AlertSeverity::MEDIUM;
            alert.type = AlertType::TRAFFIC_SPIKE;
            alert.rule_name = "Traffic Volumetric Spike";
            alert.src_ip = pkt.src_ip;
            alert.dst_ip = pkt.dst_ip;
            alert.protocol = pkt.protocol;

            std::ostringstream ss;
            ss << "Source IP " << pkt.src_ip << " generated " << total_bytes
               << " bytes within 1 second window (Threshold: " << config_.traffic_spike_bytes_per_sec << " bytes/sec).";
            alert.description = ss.str();
            alert.metric_value = static_cast<double>(total_bytes);
            alert.threshold_value = static_cast<double>(config_.traffic_spike_bytes_per_sec);

            alerts.push_back(std::move(alert));
        }
    }
}

void TrafficSpikeDetector::periodic_check(uint64_t current_time_us, std::vector<Alert>& alerts) {
    (void)alerts;
    std::unique_lock lock(mutex_);
    for (auto it = traffic_.begin(); it != traffic_.end(); ) {
        uint64_t window_start = (current_time_us > config_.traffic_spike_window_us)
                                ? (current_time_us - config_.traffic_spike_window_us) : 0;
        auto& entries = it->second.entries;
        entries.erase(
            std::remove_if(entries.begin(), entries.end(), [window_start](const PacketEntry& pe) {
                return pe.timestamp_us < window_start;
            }),
            entries.end()
        );
        if (entries.empty()) {
            it = traffic_.erase(it);
        } else {
            ++it;
        }
    }
}

void TrafficSpikeDetector::reset() {
    std::unique_lock lock(mutex_);
    traffic_.clear();
}

} // namespace netguard
