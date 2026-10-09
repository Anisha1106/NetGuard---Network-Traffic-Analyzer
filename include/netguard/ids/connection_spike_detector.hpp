#pragma once

#include "netguard/ids/detector.hpp"
#include <unordered_map>
#include <vector>
#include <shared_mutex>

namespace netguard {

class ConnectionSpikeDetector : public IDetector {
public:
    explicit ConnectionSpikeDetector(const RuleConfig& config);

    void inspect(const ParsedPacket& pkt, std::vector<Alert>& alerts) override;
    void periodic_check(uint64_t current_time_us, std::vector<Alert>& alerts) override;
    void reset() override;

private:
    struct SynTimestamp {
        uint64_t timestamp_us;
    };

    struct SrcSynState {
        std::vector<SynTimestamp> syns;
        bool alert_fired{false};
        uint64_t last_alert_time_us{0};
    };

    RuleConfig config_;
    std::unordered_map<std::string, SrcSynState> syn_states_;
    std::shared_mutex mutex_;
    uint64_t alert_counter_{0};
};

} // namespace netguard
