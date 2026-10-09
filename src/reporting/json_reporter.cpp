#include "netguard/reporting/json_reporter.hpp"
#include <sstream>
#include <fstream>
#include <iomanip>

namespace netguard {

std::string JSONReporter::generate_report(const PipelineStats& stats,
                                          const std::vector<Alert>& alerts,
                                          const std::vector<FlowMetrics>& flows) {
    std::ostringstream ss;
    ss << "{\n";
    ss << "  \"summary\": {\n";
    ss << "    \"total_packets\": " << stats.total_packets << ",\n";
    ss << "    \"valid_packets\": " << stats.valid_packets << ",\n";
    ss << "    \"malformed_packets\": " << stats.malformed_packets << ",\n";
    ss << "    \"total_bytes\": " << stats.total_bytes << ",\n";
    ss << "    \"total_alerts\": " << stats.total_alerts << ",\n";
    ss << "    \"elapsed_seconds\": " << stats.elapsed_seconds << ",\n";
    ss << "    \"packets_per_sec\": " << stats.packets_per_sec << ",\n";
    ss << "    \"megabytes_per_sec\": " << stats.megabytes_per_sec << "\n";
    ss << "  },\n";

    ss << "  \"alerts\": [\n";
    for (size_t i = 0; i < alerts.size(); ++i) {
        const auto& a = alerts[i];
        ss << "    {\n";
        ss << "      \"alert_id\": " << a.alert_id << ",\n";
        ss << "      \"timestamp_us\": " << a.timestamp_us << ",\n";
        ss << "      \"severity\": \"" << severity_to_string(a.severity) << "\",\n";
        ss << "      \"type\": \"" << alert_type_to_string(a.type) << "\",\n";
        ss << "      \"rule_name\": \"" << a.rule_name << "\",\n";
        ss << "      \"src_ip\": \"" << a.src_ip << "\",\n";
        ss << "      \"dst_ip\": \"" << a.dst_ip << "\",\n";
        ss << "      \"dst_port\": " << a.dst_port << ",\n";
        ss << "      \"protocol\": \"" << protocol_to_string(a.protocol) << "\",\n";
        ss << "      \"description\": \"" << a.description << "\",\n";
        ss << "      \"metric_value\": " << a.metric_value << ",\n";
        ss << "      \"threshold_value\": " << a.threshold_value << "\n";
        ss << "    }" << (i + 1 < alerts.size() ? "," : "") << "\n";
    }
    ss << "  ],\n";

    ss << "  \"active_flows\": [\n";
    for (size_t i = 0; i < flows.size(); ++i) {
        const auto& f = flows[i];
        ss << "    {\n";
        ss << "      \"src_ip\": \"" << f.key.src_ip << "\",\n";
        ss << "      \"dst_ip\": \"" << f.key.dst_ip << "\",\n";
        ss << "      \"src_port\": " << f.key.src_port << ",\n";
        ss << "      \"dst_port\": " << f.key.dst_port << ",\n";
        ss << "      \"protocol\": \"" << protocol_to_string(f.key.protocol) << "\",\n";
        ss << "      \"packet_count\": " << f.packet_count << ",\n";
        ss << "      \"byte_count\": " << f.byte_count << ",\n";
        ss << "      \"duration_sec\": " << f.duration_seconds() << "\n";
        ss << "    }" << (i + 1 < flows.size() ? "," : "") << "\n";
    }
    ss << "  ]\n";
    ss << "}\n";

    return ss.str();
}

bool JSONReporter::write_to_file(const std::string& filepath,
                                 const PipelineStats& stats,
                                 const std::vector<Alert>& alerts,
                                 const std::vector<FlowMetrics>& flows) {
    std::ofstream file(filepath);
    if (!file.is_open()) return false;
    file << generate_report(stats, alerts, flows);
    return true;
}

} // namespace netguard
