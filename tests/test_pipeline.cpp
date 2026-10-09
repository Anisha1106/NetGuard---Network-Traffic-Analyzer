#include <gtest/gtest.h>
#include "netguard/pipeline/processing_pipeline.hpp"
#include "netguard/ids/anomaly_detector.hpp"

using namespace netguard;

TEST(PipelineTest, MultithreadedProcessing) {
    RuleConfig cfg;
    ProcessingPipeline pipeline(500);
    pipeline.add_detector(std::make_shared<AnomalyDetector>(cfg));

    pipeline.start_workers(4);

    for (int i = 0; i < 1000; ++i) {
        RawPacket pkt;
        pkt.packet_id = i + 1;
        pkt.timestamp_us = 1000000 + i * 100;
        pkt.captured_len = 54;
        pkt.original_len = 54;
        pkt.payload.resize(54, 0x00);
        pipeline.push_packet(std::move(pkt));
    }

    pipeline.stop_and_wait();

    auto stats = pipeline.get_stats();
    EXPECT_EQ(stats.total_packets, 1000);
    EXPECT_GT(stats.elapsed_seconds, 0.0);
}
