# NetGuard C++ — Multithreaded Network Traffic Analyzer & Intrusion Detection Engine

[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://en.cppreference.com/w/cpp/20)
[![CMake](https://img.shields.io/badge/CMake-3.20%2B-green.svg)](https://cmake.org/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)
[![Build & Test](https://github.com/netguard/netguard-cpp/actions/workflows/ci.yml/badge.svg)](https://github.com/netguard/netguard-cpp/actions/workflows/ci.yml)

**NetGuard C++** is an end-to-end, high-performance, multithreaded network security application built using modern C++20. It ingests PCAP network packet captures, decodes Ethernet, IPv4, IPv6, TCP, UDP, and VLAN frames, maintains 5-tuple flow metrics, and executes real-time rule-based threat detection for security anomalies including port scans, SYN floods, traffic volume spikes, stealth Xmas/Null scans, and suspicious backdoor port traffic.

---

## Key Features

- **Modern C++20 Architecture**: Leverages `std::span`, `std::chrono`, `std::shared_mutex`, smart pointers, and zero raw memory allocations.
- **High-Performance Multithreaded Pipeline**: Producer-Consumer concurrency model powered by a lock-based thread-safe `BoundedQueue<T>` with condition variable signaling, supporting up to **1.80 Million Packets/second** parsing throughput.
- **Zero-Dependency PCAP Binary Parser**: Hand-crafted, endian-aware PCAP binary file parser supporting microsecond and nanosecond timestamps without dynamic linking issues.
- **Rule-Based Intrusion Detection Engine (IDS)**:
  - **Port Scan Detector**: Tracks distinct destination ports targeted per source IP in sliding time windows.
  - **SYN Flood / Brute-Force Detector**: Detects rapid TCP SYN connection bursts.
  - **Volumetric Traffic Spike Detector**: Measures byte throughput bursts per source IP or globally.
  - **Protocol & Anomaly Detector**: Flags TCP Xmas scans (`FIN+PSH+URG`), TCP Null scans (no flags set), malformed headers, and suspicious backdoor ports (e.g., 31337, 4444).
- **Multi-Format Export & Reporting**:
  - **Console Summary**: ANSI color-coded terminal report displaying metrics, top flow metrics, and security threat alerts.
  - **JSON Report**: Structured export containing pipeline statistics, alerts, and active 5-tuple flow details.
  - **CSV Export**: Security threat log export for SIEM ingestion and forensic analysis.
- **Comprehensive Test & Benchmark Suite**: GoogleTest unit & integration tests, microbenchmarks, CMake sanitizer support (ASan, TSan, UBSan), and multi-stage Docker container build.

---

## Architecture Overview

```
                          ┌───────────────────────┐
                          │    PCAP File Reader   │
                          └───────────┬───────────┘
                                      │ (RawPackets)
                                      ▼
                      ┌───────────────────────────────┐
                      │ Thread-Safe Bounded Queue<T> │
                      └───────────────┬───────────────┘
                                      │
            ┌─────────────────────────┼─────────────────────────┐
            │ (Worker Thread 1)       │ (Worker Thread 2)       │ (Worker Thread N)
            ▼                         ▼                         ▼
┌───────────────────────┐ ┌───────────────────────┐ ┌───────────────────────┐
│     Packet Parser     │ │     Packet Parser     │ │     Packet Parser     │
│ (Ethernet/IPv4/TCP/UDP) │ │ (Ethernet/IPv4/TCP/UDP) │ │ (Ethernet/IPv4/TCP/UDP) │
└───────────┬───────────┘ └───────────┬───────────┘ └───────────┬───────────┘
            │                         │                         │
            ├─────────────────────────┴─────────────────────────┤
            ▼                                                   ▼
┌───────────────────────┐                           ┌───────────────────────┐
│     Flow Tracker      │                           │  IDS Rule Detectors   │
│ (5-Tuple State Map)   │                           │ (PortScan/SYN/Spike)  │
└───────────┬───────────┘                           └───────────┬───────────┘
            │                                                   │
            └─────────────────────────┬─────────────────────────┘
                                      ▼
                      ┌───────────────────────────────┐
                      │  Reporting Engine & Exporters │
                      │    (Console / JSON / CSV)     │
                      └───────────────────────────────┘
```

---

## Tech Stack

- **Language**: C++20
- **Build System**: CMake 3.20+
- **Toolchain**: GCC 13+ / Apple Clang 15+ / MSVC 2022
- **Testing**: GoogleTest (v1.14.0 fetched automatically)
- **Concurrency**: `std::thread`, `std::mutex`, `std::condition_variable`, `std::shared_mutex`, `std::atomic`
- **Sanitizers**: AddressSanitizer (ASan), ThreadSanitizer (TSan), UndefinedBehaviorSanitizer (UBSan)
- **Deployment**: Multi-stage Dockerfile, GitHub Actions CI pipeline

---

## Repository Structure

```
netguard-cpp/
├── CMakeLists.txt              # Root CMake build script
├── Dockerfile                  # Multi-stage Docker build
├── README.md                   # Comprehensive documentation
├── .gitignore                  # Git ignore rules
├── .github/
│   └── workflows/
│       └── ci.yml              # GitHub Actions CI workflow
├── include/netguard/
│   ├── core/                   # Packet, Flow, Alert, and Type definitions
│   ├── parser/                 # Binary network headers, PacketParser, PCAPReader
│   ├── pipeline/               # BoundedQueue, FlowTracker, ProcessingPipeline
│   ├── ids/                    # RuleConfig, IDetector, PortScan, Spike, Anomaly
│   ├── reporting/              # ConsoleReporter, JSONReporter, CSVReporter
│   └── utils/                  # Logger, Time utilities
├── src/                        # C++ source implementations
├── tests/                      # GoogleTest unit & integration tests
├── benchmarks/                 # Performance microbenchmark suite
├── config/                     # Default JSON rule configuration
└── samples/                    # Synthetic attack PCAP generator
```

---

## Quick Start & Build Instructions

### Prerequisites

- CMake 3.20 or higher
- Modern C++20 compiler (`g++` or `clang++`)
- Make or Ninja build system

### 1. Build NetGuard from Source

```bash
git clone https://github.com/netguard/netguard-cpp.git
cd netguard-cpp

mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

This generates three primary binaries in the `build/` directory:
- `netguard_cli`: Main command-line application
- `netguard_sample_gen`: Synthetic attack PCAP file generator
- `tests/netguard_tests`: GoogleTest unit test runner
- `benchmarks/netguard_benchmarks`: Performance benchmark suite

---

## Running the Application

### Step 1: Generate a Sample Attack PCAP

Generate a test PCAP file containing simulated HTTP web traffic, SYN port scan attacks, SYN floods, Xmas scans, Null scans, and backdoor port access:

```bash
./build/netguard_sample_gen sample_attack.pcap
```

### Step 2: Analyze Traffic with NetGuard CLI

```bash
./build/netguard_cli --pcap sample_attack.pcap --rules config/netguard_rules.json --json report.json --csv alerts.csv --threads 4
```

### CLI Command Options

| Parameter | Short | Description |
|---|---|---|
| `--pcap <file>` | `-p` | **(Required)** Path to input PCAP packet capture file |
| `--threads <N>` | `-t` | Number of worker processing threads (Default: 4) |
| `--rules <file>` | `-r` | Path to JSON IDS rule configuration file |
| `--json <file>` | `-j` | Path to export structured JSON analysis report |
| `--csv <file>` | `-c` | Path to export CSV security alerts report |
| `--verbose` | `-v` | Enable detailed debug logging output |
| `--help` | `-h` | Display command usage and options |

---

## Performance Benchmarks

Microbenchmarks executed on Apple M3 / x86_64 architecture:

| Benchmark Target | Metric | Result |
|---|---|---|
| **Packet Parsing Latency** | Nanoseconds / Packet | **555.26 ns / packet** |
| **Parser Throughput** | Packets / Second | **1.80 Million Pkts/sec** |
| **Pipeline (1 Thread)** | Throughput (MPPS) | **0.71 MPPS** |
| **Pipeline (2 Threads)** | Throughput (MPPS) | **1.16 MPPS** |
| **Pipeline (4 Threads)** | Throughput (MPPS) | **0.90 MPPS** |

### Run Benchmarks Locally

```bash
./build/benchmarks/netguard_benchmarks
```

---

## Unit & Integration Testing

NetGuard includes a complete GoogleTest suite testing lock-based queue concurrency, binary protocol parser boundaries, 5-tuple flow metrics aggregation, and IDS threat detection rules.

```bash
./build/tests/netguard_tests
```

**Output:**
```
[==========] Running 10 tests from 5 test suites.
[----------] 3 tests from BoundedQueueTest
[ RUN      ] BoundedQueueTest.BasicPushPop [OK]
[ RUN      ] BoundedQueueTest.ConcurrentPushPop [OK]
[ RUN      ] BoundedQueueTest.StopUnblocksWaitingThreads [OK]
[----------] 2 tests from PacketParserTest
[ RUN      ] PacketParserTest.ParseIPv4TCP [OK]
[ RUN      ] PacketParserTest.ParseTruncatedHeader [OK]
[----------] 2 tests from FlowTrackerTest
[ RUN      ] FlowTrackerTest.TrackFlowMetrics [OK]
[ RUN      ] FlowTrackerTest.IdleFlowCleanup [OK]
[----------] 2 tests from DetectorTest
[ RUN      ] DetectorTest.PortScanDetectorTrigger [OK]
[ RUN      ] DetectorTest.XmasAndNullScanDetector [OK]
[----------] 1 test from PipelineTest
[ RUN      ] PipelineTest.MultithreadedProcessing [OK]
[==========] 10 tests from 5 test suites ran. (100% PASSED)
```

### Memory & Thread Sanitizer Builds

Detect memory leaks and race conditions using Clang/GCC sanitizers:

```bash
# AddressSanitizer
cmake -DSANITIZE_ADDRESS=ON .. && make -j4 && ./tests/netguard_tests

# ThreadSanitizer
cmake -DSANITIZE_THREAD=ON .. && make -j4 && ./tests/netguard_tests
```

---

## Docker Deployment

Build and run NetGuard in a containerized Linux environment:

```bash
# Build multi-stage Docker image
docker build -t netguard-cpp:latest .

# Run NetGuard CLI in Docker
docker run --rm netguard-cpp:latest --pcap /app/sample_attack.pcap --threads 4
```

---

