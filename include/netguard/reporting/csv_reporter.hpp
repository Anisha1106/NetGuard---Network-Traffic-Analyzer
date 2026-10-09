#pragma once

#include "netguard/core/alert.hpp"
#include "netguard/pipeline/flow_tracker.hpp"
#include <string>
#include <vector>

namespace netguard {

class CSVReporter {
public:
    static bool export_alerts(const std::string& filepath, const std::vector<Alert>& alerts);
    static bool export_flows(const std::string& filepath, const std::vector<FlowMetrics>& flows);
};

} // namespace netguard
