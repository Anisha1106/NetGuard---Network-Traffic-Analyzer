#include "netguard/ids/connection_spike_detector.hpp"
#include <algorithm>
#include <sstream>

namespace netguard {

ConnectionSpikeDetector::ConnectionSpikeDetector(const RuleConfig& config) : config_(config) {}

void ConnectionSpikeDetector::inspect(const ParsedPacket& pkt, std::vector<Alert>& alerts) {
    if (!config_.enable_connection_spike_detection || !pkt.is_valid || pkt.src_ip.empty()) {
        return;
    }

    if (pkt.protocol != Protocol::TCP || !pkt.tcp_flags.syn) {
        return;
    }

    std::unique_lock lock(mutex_);
    auto& state = syn_states_[pkt.src_ip];

    uint64_t window_start = (pkt.timestamp_us > config_.connection_spike_window_us)
                            ? (pkt.timestamp_us - config_.connection_spike_window_us) : 0;

    state.syns.erase(
        std::remove_if(state.syns.begin(), state.syns.end(), [window_start](const SynTimestamp& st) {
            return st.timestamp_us < window_start;
        }),
        state.syns.end()
    );

    state.syns.push_back({pkt.timestamp_us});

    if (state.syns.size() >= config_.connection_spike_syn_per_sec) {
        if (!state.alert_fired || (pkt.timestamp_us - state.last_alert_time_us) > config_.connection_spike_window_us) {
            state.alert_fired = true;
            state.last_alert_time_us = pkt.timestamp_us;

            Alert alert;
            alert.alert_id = ++alert_counter_;
            alert.timestamp_us = pkt.timestamp_us;
            alert.severity = AlertSeverity::HIGH;
            alert.type = AlertType::BRUTE_FORCE_ATTEMPT;
            alert.rule_name = "SYN Connection Flood / Rapid Attempts";
            alert.src_ip = pkt.src_ip;
            alert.dst_ip = pkt.dst_ip;
            alert.dst_port = pkt.dst_port;
            alert.protocol = pkt.protocol;

            std::ostringstream ss;
            ss << "Source IP " << pkt.src_ip << " initiated " << state.syns.size()
               << " TCP SYN packets in 1 second window (Threshold: " << config_.connection_spike_syn_per_sec << ").";
            alert.description = ss.str();
            alert.metric_value = static_cast<double>(state.syns.size());
            alert.threshold_value = static_cast<double>(config_.connection_spike_syn_per_sec);

            alerts.push_back(std::move(alert));
        }
    }
}

void ConnectionSpikeDetector::periodic_check(uint64_t current_time_us, std::vector<Alert>& alerts) {
    (void)alerts;
    std::unique_lock lock(mutex_);
    for (auto it = syn_states_.begin(); it != syn_states_.end(); ) {
        uint64_t window_start = (current_time_us > config_.connection_spike_window_us)
                                ? (current_time_us - config_.connection_spike_window_us) : 0;
        auto& syns = it->second.syns;
        syns.erase(
            std::remove_if(syns.begin(), syns.end(), [window_start](const SynTimestamp& st) {
                return st.timestamp_us < window_start;
            }),
            syns.end()
        );
        if (syns.empty()) {
            it = syn_states_.erase(it);
        } else {
            ++it;
        }
    }
}

void ConnectionSpikeDetector::reset() {
    std::unique_lock lock(mutex_);
    syn_states_.clear();
}

} // namespace netguard
