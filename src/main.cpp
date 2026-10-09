#include "netguard/pipeline/processing_pipeline.hpp"
#include "netguard/ids/rule_config.hpp"
#include "netguard/ids/port_scan_detector.hpp"
#include "netguard/ids/traffic_spike_detector.hpp"
#include "netguard/ids/connection_spike_detector.hpp"
#include "netguard/ids/anomaly_detector.hpp"
#include "netguard/reporting/json_reporter.hpp"
#include "netguard/reporting/csv_reporter.hpp"
#include "netguard/reporting/console_reporter.hpp"
#include "netguard/utils/logger.hpp"
#include <iostream>
#include <string>
#include <memory>

using namespace netguard;

void print_help(const char* prog) {
    std::cout << "NetGuard C++ -- Multithreaded Network Traffic Analyzer & IDS Engine\n\n"
              << "Usage: " << prog << " [options]\n\n"
              << "Options:\n"
              << "  -p, --pcap <file>         Path to PCAP capture file to analyze\n"
              << "  -t, --threads <N>         Number of worker threads (default: 4)\n"
              << "  -r, --rules <file>        Path to JSON rule configuration file\n"
              << "  -j, --json <file>         Export JSON analysis & alert report\n"
              << "  -c, --csv <file>          Export CSV security alerts report\n"
              << "  -g, --gen-sample <file>   Generate sample PCAP file with simulated attacks\n"
              << "  -v, --verbose             Enable debug log output\n"
              << "  -h, --help                Show this help message\n";
}

int main(int argc, char** argv) {
    std::string pcap_file;
    std::string rules_file;
    std::string json_output;
    std::string csv_output;
    size_t worker_threads = 4;
    bool verbose = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_help(argv[0]);
            return 0;
        } else if ((arg == "-p" || arg == "--pcap") && i + 1 < argc) {
            pcap_file = argv[++i];
        } else if ((arg == "-t" || arg == "--threads") && i + 1 < argc) {
            worker_threads = static_cast<size_t>(std::stoul(argv[++i]));
        } else if ((arg == "-r" || arg == "--rules") && i + 1 < argc) {
            rules_file = argv[++i];
        } else if ((arg == "-j" || arg == "--json") && i + 1 < argc) {
            json_output = argv[++i];
        } else if ((arg == "-c" || arg == "--csv") && i + 1 < argc) {
            csv_output = argv[++i];
        } else if (arg == "-v" || arg == "--verbose") {
            verbose = true;
        }
    }

    if (verbose) {
        Logger::instance().set_level(LogLevel::DEBUG);
    }

    if (pcap_file.empty()) {
        std::cout << "[!] No PCAP file specified. Use -p <file.pcap> or run with --help.\n";
        return 1;
    }

    Logger::instance().info("Initializing NetGuard IDS Pipeline with " + std::to_string(worker_threads) + " worker threads...");

    RuleConfig config = rules_file.empty() ? RuleConfig::load_default() : RuleConfig::load_from_file(rules_file);

    ProcessingPipeline pipeline(10000);
    pipeline.add_detector(std::make_shared<PortScanDetector>(config));
    pipeline.add_detector(std::make_shared<TrafficSpikeDetector>(config));
    pipeline.add_detector(std::make_shared<ConnectionSpikeDetector>(config));
    pipeline.add_detector(std::make_shared<AnomalyDetector>(config));

    Logger::instance().info("Analyzing PCAP file: " + pcap_file);

    if (!pipeline.process_pcap(pcap_file, worker_threads)) {
        Logger::instance().error("Failed to open or parse PCAP file: " + pcap_file);
        return 1;
    }

    auto stats = pipeline.get_stats();
    auto alerts = pipeline.get_alerts();
    auto flows = pipeline.get_flow_tracker().get_top_talkers(20);

    ConsoleReporter::print_summary(stats, alerts, flows, true);

    if (!json_output.empty()) {
        if (JSONReporter::write_to_file(json_output, stats, alerts, flows)) {
            Logger::instance().info("JSON report exported to " + json_output);
        } else {
            Logger::instance().error("Failed to write JSON report to " + json_output);
        }
    }

    if (!csv_output.empty()) {
        if (CSVReporter::export_alerts(csv_output, alerts)) {
            Logger::instance().info("CSV alerts report exported to " + csv_output);
        } else {
            Logger::instance().error("Failed to write CSV report to " + csv_output);
        }
    }

    return 0;
}
