#include "netguard/reporting/console_reporter.hpp"
#include <iostream>
#include <iomanip>

namespace netguard {

void ConsoleReporter::print_summary(const PipelineStats& stats,
                                    const std::vector<Alert>& alerts,
                                    const std::vector<FlowMetrics>& flows,
                                    bool use_colors) {
    const std::string RESET   = use_colors ? "\033[0m" : "";
    const std::string BOLD    = use_colors ? "\033[1m" : "";
    const std::string RED     = use_colors ? "\033[31m" : "";
    const std::string GREEN   = use_colors ? "\033[32m" : "";
    const std::string YELLOW  = use_colors ? "\033[33m" : "";
    const std::string CYAN    = use_colors ? "\033[36m" : "";

    std::cout << "\n" << BOLD << CYAN
              << "================================================================================\n"
              << "            NETGUARD C++ :: TRAFFIC ANALYZER & IDS ENGINE SUMMARY               \n"
              << "================================================================================\n"
              << RESET;

    std::cout << BOLD << " [Pipeline Statistics]\n" << RESET;
    std::cout << "  - Total Packets Processed: " << stats.total_packets << "\n";
    std::cout << "  - Valid Packets:           " << GREEN << stats.valid_packets << RESET << "\n";
    if (stats.malformed_packets > 0) {
        std::cout << "  - Malformed Packets:       " << RED << stats.malformed_packets << RESET << "\n";
    }
    std::cout << "  - Total Bytes Analyzed:    " << stats.total_bytes << " bytes ("
              << std::fixed << std::setprecision(2) << (stats.total_bytes / (1024.0 * 1024.0)) << " MB)\n";
    std::cout << "  - Processing Time:         " << stats.elapsed_seconds << " sec\n";
    std::cout << "  - Throughput (Packets):    " << BOLD << stats.packets_per_sec << " pkt/sec" << RESET << "\n";
    std::cout << "  - Throughput (Bandwidth):  " << BOLD << stats.megabytes_per_sec << " MB/sec" << RESET << "\n";

    std::cout << "\n" << BOLD << " [Security Intrusion Detection Alerts] ("
              << (alerts.empty() ? GREEN : RED) << alerts.size() << " detected" << RESET << ")\n";

    if (alerts.empty()) {
        std::cout << GREEN << "  [✓] No security threats or suspicious activity detected.\n" << RESET;
    } else {
        std::cout << "  ----------------------------------------------------------------------------\n";
        std::cout << "  ID | Severity | Alert Type         | Source IP -> Dest IP         | Rule\n";
        std::cout << "  ----------------------------------------------------------------------------\n";
        for (const auto& a : alerts) {
            std::string sev_color = (a.severity == AlertSeverity::CRITICAL || a.severity == AlertSeverity::HIGH) ? RED : YELLOW;
            std::cout << "  " << std::setw(2) << a.alert_id << " | "
                      << sev_color << std::setw(8) << severity_to_string(a.severity) << RESET << " | "
                      << std::setw(18) << alert_type_to_string(a.type) << " | "
                      << std::setw(15) << a.src_ip << " -> " << std::setw(15) << a.dst_ip << " | "
                      << a.rule_name << "\n";
            std::cout << "     Detail: " << a.description << "\n";
        }
        std::cout << "  ----------------------------------------------------------------------------\n";
    }

    std::cout << "\n" << BOLD << " [Top Network Flows] (" << flows.size() << " active flows)\n" << RESET;
    if (!flows.empty()) {
        std::cout << "  ----------------------------------------------------------------------------\n";
        std::cout << "  Source IP        | Dest IP          | Proto | Packets  | Total Bytes  \n";
        std::cout << "  ----------------------------------------------------------------------------\n";
        size_t print_count = std::min<size_t>(flows.size(), 10);
        for (size_t i = 0; i < print_count; ++i) {
            const auto& f = flows[i];
            std::cout << "  " << std::setw(16) << f.key.src_ip << " | "
                      << std::setw(16) << f.key.dst_ip << " | "
                      << std::setw(5)  << protocol_to_string(f.key.protocol) << " | "
                      << std::setw(8)  << f.packet_count << " | "
                      << std::setw(12) << f.byte_count << "\n";
        }
        std::cout << "  ----------------------------------------------------------------------------\n";
    }

    std::cout << BOLD << CYAN << "================================================================================\n\n" << RESET;
}

} // namespace netguard
