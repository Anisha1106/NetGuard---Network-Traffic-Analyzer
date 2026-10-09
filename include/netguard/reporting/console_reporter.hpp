#pragma once

#include "netguard/core/alert.hpp"
#include "netguard/pipeline/flow_tracker.hpp"
#include "netguard/pipeline/processing_pipeline.hpp"
#include <string>
#include <vector>

namespace netguard {

class ConsoleReporter {
public:
    static void print_summary(const PipelineStats& stats,
                              const std::vector<Alert>& alerts,
                              const std::vector<FlowMetrics>& flows,
                              bool use_colors = true);
};

} // namespace netguard
