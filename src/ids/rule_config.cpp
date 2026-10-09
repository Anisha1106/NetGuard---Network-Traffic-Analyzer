#include "netguard/ids/rule_config.hpp"
#include <fstream>
#include <sstream>
#include <iostream>

namespace netguard {

RuleConfig RuleConfig::load_default() {
    return RuleConfig{};
}

RuleConfig RuleConfig::load_from_file(const std::string& filepath) {
    RuleConfig config = load_default();
    std::ifstream file(filepath);
    if (!file.is_open()) {
        return config;
    }

    std::string line;
    while (std::getline(file, line)) {
        // Simple key:value JSON style parsing without external heavy dependencies
        if (line.find("\"port_scan_threshold_ports\"") != std::string::npos) {
            auto pos = line.find(':');
            if (pos != std::string::npos) config.port_scan_threshold_ports = std::stoul(line.substr(pos + 1));
        } else if (line.find("\"traffic_spike_bytes_per_sec\"") != std::string::npos) {
            auto pos = line.find(':');
            if (pos != std::string::npos) config.traffic_spike_bytes_per_sec = std::stoull(line.substr(pos + 1));
        } else if (line.find("\"connection_spike_syn_per_sec\"") != std::string::npos) {
            auto pos = line.find(':');
            if (pos != std::string::npos) config.connection_spike_syn_per_sec = std::stoul(line.substr(pos + 1));
        }
    }
    return config;
}

bool RuleConfig::save_to_file(const std::string& filepath) const {
    std::ofstream file(filepath);
    if (!file.is_open()) return false;

    file << "{\n"
         << "  \"enable_port_scan_detection\": " << (enable_port_scan_detection ? "true" : "false") << ",\n"
         << "  \"port_scan_threshold_ports\": " << port_scan_threshold_ports << ",\n"
         << "  \"port_scan_window_us\": " << port_scan_window_us << ",\n"
         << "  \"enable_traffic_spike_detection\": " << (enable_traffic_spike_detection ? "true" : "false") << ",\n"
         << "  \"traffic_spike_bytes_per_sec\": " << traffic_spike_bytes_per_sec << ",\n"
         << "  \"traffic_spike_window_us\": " << traffic_spike_window_us << ",\n"
         << "  \"enable_connection_spike_detection\": " << (enable_connection_spike_detection ? "true" : "false") << ",\n"
         << "  \"connection_spike_syn_per_sec\": " << connection_spike_syn_per_sec << ",\n"
         << "  \"enable_anomaly_detection\": " << (enable_anomaly_detection ? "true" : "false") << "\n"
         << "}\n";
    return true;
}

} // namespace netguard
