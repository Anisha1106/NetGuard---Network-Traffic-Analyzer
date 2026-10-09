#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <unordered_set>

namespace netguard {

struct RuleConfig {
    // Port Scan Detection
    bool enable_port_scan_detection{true};
    uint32_t port_scan_threshold_ports{10};       // Distinct ports within window
    uint64_t port_scan_window_us{5000000ULL};     // 5 second sliding window

    // Traffic Spike Detection
    bool enable_traffic_spike_detection{true};
    uint64_t traffic_spike_bytes_per_sec{10000000ULL}; // 10 MB/s
    uint64_t traffic_spike_window_us{1000000ULL};      // 1 second sliding window

    // Connection Spike / SYN Flood Detection
    bool enable_connection_spike_detection{true};
    uint32_t connection_spike_syn_per_sec{50};    // 50 SYNs/sec per IP
    uint64_t connection_spike_window_us{1000000ULL};

    // Protocol & Port Anomaly Detection
    bool enable_anomaly_detection{true};
    bool detect_xmas_scans{true};
    bool detect_null_scans{true};
    bool detect_suspicious_ports{true};
    std::unordered_set<uint16_t> suspicious_ports{21, 23, 1337, 31337, 4444, 6667, 8888};

    static RuleConfig load_default();
    static RuleConfig load_from_file(const std::string& filepath);
    bool save_to_file(const std::string& filepath) const;
};

} // namespace netguard
