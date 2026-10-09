#include "netguard/pipeline/flow_tracker.hpp"
#include <algorithm>

namespace netguard {

void FlowTracker::update_flow(const ParsedPacket& pkt) {
    if (!pkt.is_valid || pkt.ethertype == EtherType::UNKNOWN) {
        return;
    }

    FlowKey key{pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol};

    std::unique_lock lock(mutex_);
    auto [it, inserted] = flows_.try_emplace(key, FlowMetrics{key, 0, 0, pkt.timestamp_us, pkt.timestamp_us, 0, 0, 0});
    it->second.update(pkt);
}

size_t FlowTracker::active_flow_count() const {
    std::shared_lock lock(mutex_);
    return flows_.size();
}

std::vector<FlowMetrics> FlowTracker::get_active_flows() const {
    std::shared_lock lock(mutex_);
    std::vector<FlowMetrics> result;
    result.reserve(flows_.size());
    for (const auto& [key, metrics] : flows_) {
        result.push_back(metrics);
    }
    return result;
}

std::vector<FlowMetrics> FlowTracker::get_top_talkers(size_t top_n) const {
    auto flows = get_active_flows();
    std::sort(flows.begin(), flows.end(), [](const FlowMetrics& a, const FlowMetrics& b) {
        return a.byte_count > b.byte_count;
    });
    if (flows.size() > top_n) {
        flows.resize(top_n);
    }
    return flows;
}

size_t FlowTracker::cleanup_idle_flows(uint64_t current_time_us, uint64_t idle_timeout_us) {
    std::unique_lock lock(mutex_);
    size_t removed = 0;
    for (auto it = flows_.begin(); it != flows_.end(); ) {
        if (current_time_us > it->second.last_seen_us &&
            (current_time_us - it->second.last_seen_us) > idle_timeout_us) {
            it = flows_.erase(it);
            removed++;
        } else {
            ++it;
        }
    }
    return removed;
}

void FlowTracker::reset() {
    std::unique_lock lock(mutex_);
    flows_.clear();
}

} // namespace netguard
