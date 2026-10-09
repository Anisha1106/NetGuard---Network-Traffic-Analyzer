#include <gtest/gtest.h>
#include "netguard/pipeline/flow_tracker.hpp"

using namespace netguard;

TEST(FlowTrackerTest, TrackFlowMetrics) {
    FlowTracker tracker;

    ParsedPacket pkt1;
    pkt1.is_valid = true;
    pkt1.ethertype = EtherType::IPv4;
    pkt1.src_ip = "192.168.1.5";
    pkt1.dst_ip = "8.8.8.8";
    pkt1.src_port = 54321;
    pkt1.dst_port = 53;
    pkt1.protocol = Protocol::UDP;
    pkt1.timestamp_us = 1000000;
    pkt1.payload_len = 64;

    tracker.update_flow(pkt1);

    EXPECT_EQ(tracker.active_flow_count(), 1);

    ParsedPacket pkt2 = pkt1;
    pkt2.timestamp_us = 2000000;
    pkt2.payload_len = 128;

    tracker.update_flow(pkt2);

    EXPECT_EQ(tracker.active_flow_count(), 1);

    auto flows = tracker.get_active_flows();
    ASSERT_EQ(flows.size(), 1);
    EXPECT_EQ(flows[0].packet_count, 2);
    EXPECT_EQ(flows[0].byte_count, 192);
    EXPECT_DOUBLE_EQ(flows[0].duration_seconds(), 1.0);
}

TEST(FlowTrackerTest, IdleFlowCleanup) {
    FlowTracker tracker;

    ParsedPacket pkt;
    pkt.is_valid = true;
    pkt.ethertype = EtherType::IPv4;
    pkt.src_ip = "10.0.0.1";
    pkt.dst_ip = "10.0.0.2";
    pkt.src_port = 100;
    pkt.dst_port = 200;
    pkt.protocol = Protocol::TCP;
    pkt.timestamp_us = 1000000; // 1s

    tracker.update_flow(pkt);
    EXPECT_EQ(tracker.active_flow_count(), 1);

    // Cleanup idle flows after 10s (timeout 5s)
    size_t removed = tracker.cleanup_idle_flows(10000000, 5000000);
    EXPECT_EQ(removed, 1);
    EXPECT_EQ(tracker.active_flow_count(), 0);
}
