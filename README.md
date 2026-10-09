# NetGuard

<p align="center">
  <img src="https://img.shields.io/badge/C%2B%2B-20-blue.svg" alt="C++20" />
  <img src="https://img.shields.io/badge/CMake-3.20%2B-green.svg" alt="CMake 3.20+" />
  <img src="https://img.shields.io/badge/build-passing-brightgreen.svg" alt="Build passing" />
  <img src="https://img.shields.io/badge/tests-10%2F10-success.svg" alt="Tests" />
</p>

NetGuard is a C++20 network traffic analyzer and intrusion detection engine designed for offline PCAP inspection, flow tracking, and threat detection. It parses packet captures, reconstructs flow-level behavior, and detects suspicious networking activity such as port scans, SYN floods, stealth scans, and backdoor port access.

This project is built to be practical, testable, and easy to run from a clean repo checkout with modern CMake tooling and CI automation.

## Why this project

NetGuard demonstrates a complete end-to-end workflow for packet analysis and threat detection:

- low-level packet parsing from PCAP files
- flow aggregation and protocol inspection
- security rule evaluation and alert generation
- console, JSON, and CSV reporting
- concurrency-safe worker pipeline processing
- benchmark and unit test validation

This project was designed to highlight practical systems-programming skills including networking fundamentals, multithreaded design, memory-safe data flow, and CI-driven validation.

## Project highlights

- Built a C++20 packet analysis engine from scratch for offline intrusion detection workloads
- Implemented a producer/consumer processing pipeline to handle traffic analysis at scale
- Parsed raw packet data and reconstructed flow-level telemetry using 5-tuple tracking
- Added rule-based detection logic for port scans, SYN floods, stealth scans, and suspicious ports
- Exported analysis results in multiple formats for operational use and forensic review
- Verified correctness through 10 automated unit and integration tests
- Enabled repeatable builds through CMake presets, Docker support, and GitHub Actions pipelines

## Key features

- PCAP file ingestion and packet decoding
- Ethernet, IPv4/IPv6, TCP, and UDP parsing
- 5-tuple flow tracking and metric aggregation
- IDS-style detection for:
  - port scans
  - SYN flood / brute-force attempts
  - Xmas and Null scans
  - suspicious port activity
  - traffic spikes
- Multi-format reporting via console, JSON, and CSV
- Threaded processing pipeline with producer/consumer design
- GoogleTest validation and performance benchmarks
- Docker and CI support for repeatable builds

## Project architecture

```text
PCAP Input
   │
   ▼
Packet Reader / Parser
   │
   ▼
Bounded Queue
   │
   ├── Worker Threads
   │      ├── Flow Tracking
   │      ├── Rule Matching
   │      └── Alert Generation
   │
   ▼
Reporter Layer
   ├── Console
   ├── JSON
   └── CSV
```

## Repository layout

```text
.
├── CMakeLists.txt
├── CMakePresets.json
├── Dockerfile
├── Makefile
├── LICENSE
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
├── .github/
│   ├── workflows/
│   ├── ISSUE_TEMPLATE/
│   ├── dependabot.yml
│   ├── pull_request_template.md
│   └── CODEOWNERS
├── config/
│   └── netguard_rules.json
├── include/
│   └── netguard/
├── src/
├── samples/
├── tests/
├── benchmarks/
├── build/
├── .editorconfig
├── .clang-format
├── .dockerignore
├── .gitignore
└── .vscode/
```

## Requirements

- CMake 3.20+
- C++20 compiler (GCC, Clang, or Apple Clang)
- Make or Ninja
- libpcap development headers

## Quick start

```bash
git clone https://github.com/Anisha1106/NetGuard---Network-Traffic-Analyzer.git
cd "NetGuard - Network Traffic Analyzer"

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

## Run the analyzer

Generate a synthetic attack capture and analyze it:

```bash
./build/netguard_sample_gen sample_attack.pcap
./build/netguard_cli --pcap sample_attack.pcap --rules config/netguard_rules.json --json report.json --csv alerts.csv --threads 4
```

## CLI usage

```text
--pcap, -p        Input PCAP file
--rules, -r       IDS rule configuration file
--json, -j        JSON report output path
--csv, -c         CSV alerts output path
--threads, -t     Worker thread count
--verbose, -v     Verbose logging
--help, -h        Show usage
```

## Testing

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
./build/tests/netguard_tests
```

## Benchmarks

```bash
./build/benchmarks/netguard_benchmarks
```

## Example output

A generated sample traffic run identifies suspicious network behavior and exports the results to both JSON and CSV.

```text
[Security Intrusion Detection Alerts] (10 detected)
  1 | HIGH | PORT_SCAN | 192.168.1.50 -> 192.168.1.1
  2 | HIGH | BRUTE_FORCE_ATTEMPT | 10.0.0.66 -> 192.168.1.1
  3 | HIGH | XMAS_SCAN | 192.168.1.77 -> 192.168.1.1
  4 | HIGH | NULL_SCAN | 192.168.1.88 -> 192.168.1.1
```

## Docker

```bash
docker build -t netguard-cpp:latest .
docker run --rm netguard-cpp:latest --pcap /app/sample_attack.pcap --threads 4
```

## CI and release

The project includes automated validation with GitHub Actions and a release pipeline for tagged builds.

- CI workflow: [.github/workflows/ci.yml](.github/workflows/ci.yml)
- Release workflow: [.github/workflows/release.yml](.github/workflows/release.yml)
- Install and packaging support: [CMakeLists.txt](CMakeLists.txt)

## Contributing

Please review [CONTRIBUTING.md](CONTRIBUTING.md) for local development and pull request expectations.

## Security

For vulnerability reports, see [SECURITY.md](SECURITY.md).

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).

