#pragma once

#include "netguard/core/flow.hpp"
#include "netguard/core/packet.hpp"
#include <unordered_map>
#include <shared_mutex>
#include <vector>

namespace netguard {

class FlowTracker {
public:
    FlowTracker() = default;

    void update_flow(const ParsedPacket& pkt);

    size_t active_flow_count() const;
    std::vector<FlowMetrics> get_active_flows() const;
    std::vector<FlowMetrics> get_top_talkers(size_t top_n = 10) const;

    size_t cleanup_idle_flows(uint64_t current_time_us, uint64_t idle_timeout_us);
    void reset();

private:
    std::unordered_map<FlowKey, FlowMetrics, FlowKeyHash> flows_;
    mutable std::shared_mutex mutex_;
};

} // namespace netguard
