#pragma once

#include "netguard/core/alert.hpp"
#include "netguard/pipeline/flow_tracker.hpp"
#include "netguard/pipeline/processing_pipeline.hpp"
#include <string>
#include <vector>

namespace netguard {

class JSONReporter {
public:
    static std::string generate_report(const PipelineStats& stats,
                                       const std::vector<Alert>& alerts,
                                       const std::vector<FlowMetrics>& flows);

    static bool write_to_file(const std::string& filepath,
                              const PipelineStats& stats,
                              const std::vector<Alert>& alerts,
                              const std::vector<FlowMetrics>& flows);
};

} // namespace netguard
