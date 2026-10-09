#include "netguard/pipeline/processing_pipeline.hpp"
#include "netguard/parser/pcap_reader.hpp"
#include "netguard/parser/packet_parser.hpp"
#include <iostream>
#include <chrono>

namespace netguard {

ProcessingPipeline::ProcessingPipeline(size_t queue_capacity)
    : queue_capacity_(queue_capacity), queue_(queue_capacity) {}

ProcessingPipeline::~ProcessingPipeline() {
    stop_and_wait();
}

void ProcessingPipeline::add_detector(std::shared_ptr<IDetector> detector) {
    detectors_.push_back(std::move(detector));
}

void ProcessingPipeline::start_workers(size_t worker_threads) {
    if (is_running_) return;

    is_running_ = true;
    start_time_ = std::chrono::high_resolution_clock::now();
    workers_.reserve(worker_threads);

    for (size_t i = 0; i < worker_threads; ++i) {
        workers_.emplace_back(&ProcessingPipeline::worker_loop, this);
    }
}

void ProcessingPipeline::push_packet(RawPacket pkt) {
    total_packets_++;
    total_bytes_ += pkt.payload.size();
    queue_.push(std::move(pkt));
}

void ProcessingPipeline::stop_and_wait() {
    if (!is_running_) return;

    queue_.stop();
    for (auto& w : workers_) {
        if (w.joinable()) {
            w.join();
        }
    }
    workers_.clear();
    is_running_ = false;
    end_time_ = std::chrono::high_resolution_clock::now();
}

void ProcessingPipeline::worker_loop() {
    RawPacket raw;
    std::vector<Alert> local_alerts;

    while (queue_.pop(raw)) {
        ParsedPacket parsed = PacketParser::parse(raw);
        if (parsed.is_valid) {
            valid_packets_++;
            flow_tracker_.update_flow(parsed);
        } else {
            malformed_packets_++;
        }

        local_alerts.clear();
        for (auto& detector : detectors_) {
            detector->inspect(parsed, local_alerts);
        }

        if (!local_alerts.empty()) {
            std::lock_guard lock(alerts_mutex_);
            alerts_.insert(alerts_.end(), local_alerts.begin(), local_alerts.end());
        }
    }
}

bool ProcessingPipeline::process_pcap(const std::string& pcap_path, size_t worker_threads) {
    PCAPReader reader(pcap_path);
    if (!reader.open()) {
        return false;
    }

    start_workers(worker_threads);

    RawPacket pkt;
    while (reader.read_next_packet(pkt)) {
        push_packet(std::move(pkt));
    }

    reader.close();
    stop_and_wait();
    return true;
}

std::vector<Alert> ProcessingPipeline::get_alerts() const {
    std::lock_guard lock(alerts_mutex_);
    return alerts_;
}

PipelineStats ProcessingPipeline::get_stats() const {
    PipelineStats stats;
    stats.total_packets = total_packets_.load();
    stats.valid_packets = valid_packets_.load();
    stats.malformed_packets = malformed_packets_.load();
    stats.total_bytes = total_bytes_.load();

    {
        std::lock_guard lock(alerts_mutex_);
        stats.total_alerts = alerts_.size();
    }

    auto end = is_running_ ? std::chrono::high_resolution_clock::now() : end_time_;
    std::chrono::duration<double> dur = end - start_time_;
    stats.elapsed_seconds = dur.count();

    if (stats.elapsed_seconds > 0.0) {
        stats.packets_per_sec = stats.total_packets / stats.elapsed_seconds;
        stats.megabytes_per_sec = (stats.total_bytes / (1024.0 * 1024.0)) / stats.elapsed_seconds;
    }

    return stats;
}

void ProcessingPipeline::reset() {
    stop_and_wait();
    total_packets_ = 0;
    valid_packets_ = 0;
    malformed_packets_ = 0;
    total_bytes_ = 0;
    {
        std::lock_guard lock(alerts_mutex_);
        alerts_.clear();
    }
    flow_tracker_.reset();
    for (auto& detector : detectors_) {
        detector->reset();
    }
}

} // namespace netguard
