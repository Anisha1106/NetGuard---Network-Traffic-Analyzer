#include <gtest/gtest.h>
#include "netguard/ids/port_scan_detector.hpp"
#include "netguard/ids/anomaly_detector.hpp"
#include "netguard/ids/connection_spike_detector.hpp"

using namespace netguard;

TEST(DetectorTest, PortScanDetectorTrigger) {
    RuleConfig cfg;
    cfg.enable_port_scan_detection = true;
    cfg.port_scan_threshold_ports = 5;
    cfg.port_scan_window_us = 5000000;

    PortScanDetector detector(cfg);
    std::vector<Alert> alerts;

    uint64_t ts = 1000000;
    for (uint16_t port = 10; port < 15; ++port) {
        ParsedPacket pkt;
        pkt.is_valid = true;
        pkt.src_ip = "192.168.1.100";
        pkt.dst_ip = "192.168.1.1";
        pkt.src_port = 40000;
        pkt.dst_port = port;
        pkt.protocol = Protocol::TCP;
        pkt.timestamp_us = (ts += 1000);

        detector.inspect(pkt, alerts);
    }

    EXPECT_GE(alerts.size(), 1);
    EXPECT_EQ(alerts[0].type, AlertType::PORT_SCAN);
    EXPECT_EQ(alerts[0].src_ip, "192.168.1.100");
}

TEST(DetectorTest, XmasAndNullScanDetector) {
    RuleConfig cfg;
    cfg.enable_anomaly_detection = true;
    cfg.detect_xmas_scans = true;
    cfg.detect_null_scans = true;

    AnomalyDetector detector(cfg);
    std::vector<Alert> alerts;

    // Xmas packet
    ParsedPacket xmas_pkt;
    xmas_pkt.is_valid = true;
    xmas_pkt.src_ip = "10.0.0.5";
    xmas_pkt.dst_ip = "10.0.0.1";
    xmas_pkt.protocol = Protocol::TCP;
    xmas_pkt.tcp_flags.fin = true;
    xmas_pkt.tcp_flags.psh = true;
    xmas_pkt.tcp_flags.urg = true;

    detector.inspect(xmas_pkt, alerts);
    ASSERT_EQ(alerts.size(), 1);
    EXPECT_EQ(alerts[0].type, AlertType::XMAS_SCAN);

    // Null packet
    alerts.clear();
    ParsedPacket null_pkt;
    null_pkt.is_valid = true;
    null_pkt.src_ip = "10.0.0.6";
    null_pkt.dst_ip = "10.0.0.1";
    null_pkt.protocol = Protocol::TCP;

    detector.inspect(null_pkt, alerts);
    ASSERT_EQ(alerts.size(), 1);
    EXPECT_EQ(alerts[0].type, AlertType::NULL_SCAN);
}
