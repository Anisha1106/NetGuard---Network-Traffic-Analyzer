#pragma once

#include "netguard/ids/detector.hpp"
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <shared_mutex>

namespace netguard {

class PortScanDetector : public IDetector {
public:
    explicit PortScanDetector(const RuleConfig& config);

    void inspect(const ParsedPacket& pkt, std::vector<Alert>& alerts) override;
    void periodic_check(uint64_t current_time_us, std::vector<Alert>& alerts) override;
    void reset() override;

private:
    struct TargetPort {
        std::string dst_ip;
        uint16_t dst_port;
        uint64_t timestamp_us;
    };

    struct SrcRecord {
        std::vector<TargetPort> targets;
        bool alert_fired{false};
        uint64_t last_alert_time_us{0};
    };

    RuleConfig config_;
    std::unordered_map<std::string, SrcRecord> records_;
    std::shared_mutex mutex_;
    uint64_t alert_counter_{0};
};

} // namespace netguard
