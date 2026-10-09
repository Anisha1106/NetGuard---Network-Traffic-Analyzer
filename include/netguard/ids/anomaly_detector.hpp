#pragma once

#include "netguard/ids/detector.hpp"
#include <vector>
#include <mutex>

namespace netguard {

class AnomalyDetector : public IDetector {
public:
    explicit AnomalyDetector(const RuleConfig& config);

    void inspect(const ParsedPacket& pkt, std::vector<Alert>& alerts) override;
    void periodic_check(uint64_t current_time_us, std::vector<Alert>& alerts) override;
    void reset() override;

private:
    RuleConfig config_;
    std::mutex mutex_;
    uint64_t alert_counter_{0};
};

} // namespace netguard
