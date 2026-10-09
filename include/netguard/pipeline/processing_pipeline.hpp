#pragma once

#include "netguard/core/packet.hpp"
#include "netguard/core/alert.hpp"
#include "netguard/pipeline/bounded_queue.hpp"
#include "netguard/pipeline/flow_tracker.hpp"
#include "netguard/ids/detector.hpp"
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <memory>

namespace netguard {

struct PipelineStats {
    uint64_t total_packets{0};
    uint64_t valid_packets{0};
    uint64_t malformed_packets{0};
    uint64_t total_bytes{0};
    uint64_t total_alerts{0};
    double elapsed_seconds{0.0};
    double packets_per_sec{0.0};
    double megabytes_per_sec{0.0};
};

class ProcessingPipeline {
public:
    explicit ProcessingPipeline(size_t queue_capacity = 10000);
    ~ProcessingPipeline();

    void add_detector(std::shared_ptr<IDetector> detector);
    
    // Process PCAP file using multi-worker pipeline
    bool process_pcap(const std::string& pcap_path, size_t worker_threads = 4);

    // Push individual packet manually (e.g. for testing)
    void push_packet(RawPacket pkt);
    void start_workers(size_t worker_threads = 4);
    void stop_and_wait();

    std::vector<Alert> get_alerts() const;
    const FlowTracker& get_flow_tracker() const { return flow_tracker_; }
    FlowTracker& get_flow_tracker() { return flow_tracker_; }
    PipelineStats get_stats() const;
    void reset();

private:
    void worker_loop();

    size_t queue_capacity_;
    BoundedQueue<RawPacket> queue_;
    FlowTracker flow_tracker_;
    std::vector<std::shared_ptr<IDetector>> detectors_;
    std::vector<std::thread> workers_;

    std::atomic<bool> is_running_{false};
    std::atomic<uint64_t> total_packets_{0};
    std::atomic<uint64_t> valid_packets_{0};
    std::atomic<uint64_t> malformed_packets_{0};
    std::atomic<uint64_t> total_bytes_{0};

    mutable std::mutex alerts_mutex_;
    std::vector<Alert> alerts_;

    std::chrono::high_resolution_clock::time_point start_time_;
    std::chrono::high_resolution_clock::time_point end_time_;
};

} // namespace netguard
