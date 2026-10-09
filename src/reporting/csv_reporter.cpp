#include "netguard/reporting/csv_reporter.hpp"
#include <fstream>

namespace netguard {

bool CSVReporter::export_alerts(const std::string& filepath, const std::vector<Alert>& alerts) {
    std::ofstream file(filepath);
    if (!file.is_open()) return false;

    file << "AlertID,TimestampUS,Severity,Type,RuleName,SrcIP,DstIP,DstPort,Protocol,MetricValue,ThresholdValue,Description\n";

    for (const auto& a : alerts) {
        file << a.alert_id << ","
             << a.timestamp_us << ","
             << severity_to_string(a.severity) << ","
             << alert_type_to_string(a.type) << ",\""
             << a.rule_name << "\","
             << a.src_ip << ","
             << a.dst_ip << ","
             << a.dst_port << ","
             << protocol_to_string(a.protocol) << ","
             << a.metric_value << ","
             << a.threshold_value << ",\""
             << a.description << "\"\n";
    }

    return true;
}

bool CSVReporter::export_flows(const std::string& filepath, const std::vector<FlowMetrics>& flows) {
    std::ofstream file(filepath);
    if (!file.is_open()) return false;

    file << "SrcIP,DstIP,SrcPort,DstPort,Protocol,PacketCount,ByteCount,DurationSec,PacketsPerSec,BytesPerSec\n";

    for (const auto& f : flows) {
        file << f.key.src_ip << ","
             << f.key.dst_ip << ","
             << f.key.src_port << ","
             << f.key.dst_port << ","
             << protocol_to_string(f.key.protocol) << ","
             << f.packet_count << ","
             << f.byte_count << ","
             << f.duration_seconds() << ","
             << f.packets_per_second() << ","
             << f.bytes_per_second() << "\n";
    }

    return true;
}

} // namespace netguard
