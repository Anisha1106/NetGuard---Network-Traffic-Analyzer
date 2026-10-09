#include "netguard/pipeline/processing_pipeline.hpp"
#include "netguard/parser/packet_parser.hpp"
#include "netguard/ids/port_scan_detector.hpp"
#include "netguard/ids/traffic_spike_detector.hpp"
#include "netguard/ids/anomaly_detector.hpp"
#include <iostream>
#include <chrono>
#include <vector>
#include <iomanip>

using namespace netguard;

int main() {
    std::cout << "=========================================================\n";
    std::cout << "         NETGUARD C++ PERFORMANCE BENCHMARKS             \n";
    std::cout << "=========================================================\n\n";

    // Benchmark 1: Packet Parser Throughput
    {
        const size_t PARSE_COUNT = 1000000; // 1 million packets
        RawPacket raw;
        raw.payload.resize(54, 0); // Minimal Ethernet+IP+TCP header bytes
        raw.payload[12] = 0x08; raw.payload[13] = 0x00; // IPv4
        raw.payload[14] = 0x45; // IHL
        raw.payload[23] = 0x06; // TCP

        auto t1 = std::chrono::high_resolution_clock::now();
        size_t valid_cnt = 0;
        for (size_t i = 0; i < PARSE_COUNT; ++i) {
            auto pkt = PacketParser::parse(raw);
            if (pkt.is_valid) valid_cnt++;
        }
        auto t2 = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> dur = t2 - t1;

        double pkts_per_sec = PARSE_COUNT / dur.count();
        double ns_per_pkt = (dur.count() * 1e9) / PARSE_COUNT;

        std::cout << " [1] Packet Parsing Benchmark:\n";
        std::cout << "     - Total Packets Parsed: " << PARSE_COUNT << "\n";
        std::cout << "     - Duration:             " << std::fixed << std::setprecision(4) << dur.count() << " sec\n";
        std::cout << "     - Throughput:           " << std::setprecision(2) << (pkts_per_sec / 1e6) << " Million Packets/sec\n";
        std::cout << "     - Latency per Packet:   " << std::setprecision(2) << ns_per_pkt << " ns/packet\n\n";
    }

    // Benchmark 2: Multithreaded Pipeline Throughput
    for (size_t num_threads : {1, 2, 4, 8}) {
        const size_t PKT_COUNT = 500000;
        RuleConfig cfg;
        ProcessingPipeline pipeline(10000);
        pipeline.add_detector(std::make_shared<PortScanDetector>(cfg));
        pipeline.add_detector(std::make_shared<TrafficSpikeDetector>(cfg));
        pipeline.add_detector(std::make_shared<AnomalyDetector>(cfg));

        pipeline.start_workers(num_threads);

        auto t1 = std::chrono::high_resolution_clock::now();
        for (size_t i = 0; i < PKT_COUNT; ++i) {
            RawPacket raw;
            raw.packet_id = i;
            raw.timestamp_us = 1000000 + i * 10;
            raw.payload.resize(64, 0);
            raw.payload[12] = 0x08; raw.payload[13] = 0x00;
            raw.payload[14] = 0x45;
            raw.payload[23] = 0x06;
            pipeline.push_packet(std::move(raw));
        }

        pipeline.stop_and_wait();
        auto t2 = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> dur = t2 - t1;

        double mpps = (PKT_COUNT / dur.count()) / 1e6;

        std::cout << " [2] Pipeline Benchmark (" << num_threads << " Worker Threads):\n";
        std::cout << "     - Packets:     " << PKT_COUNT << "\n";
        std::cout << "     - Time:        " << std::setprecision(4) << dur.count() << " sec\n";
        std::cout << "     - Throughput:  " << std::setprecision(2) << mpps << " MPPS\n\n";
    }

    std::cout << "=========================================================\n";
    return 0;
}
