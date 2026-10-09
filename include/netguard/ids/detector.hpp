#pragma once

#include "netguard/core/packet.hpp"
#include "netguard/core/alert.hpp"
#include "netguard/ids/rule_config.hpp"
#include <vector>

namespace netguard {

class IDetector {
public:
    virtual ~IDetector() = default;

    virtual void inspect(const ParsedPacket& pkt, std::vector<Alert>& alerts) = 0;
    virtual void periodic_check(uint64_t current_time_us, std::vector<Alert>& alerts) = 0;
    virtual void reset() = 0;
};

} // namespace netguard
