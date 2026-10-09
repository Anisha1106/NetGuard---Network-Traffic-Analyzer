# Build Stage
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    g++ \
    gdb \
    libpcap-dev \
    git \
    python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN mkdir -p build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON -DBUILD_BENCHMARKS=ON .. && \
    make -j$(nproc)

# Run Tests during image build
RUN cd build && ./tests/netguard_tests

# Runtime Stage
FROM ubuntu:24.04 AS runner

RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/build/netguard_cli /usr/local/bin/netguard_cli
COPY --from=builder /app/build/netguard_sample_gen /usr/local/bin/netguard_sample_gen
COPY --from=builder /app/build/benchmarks/netguard_benchmarks /usr/local/bin/netguard_benchmarks
COPY --from=builder /app/config/netguard_rules.json /app/config/netguard_rules.json

# Generate sample PCAP inside container
RUN netguard_sample_gen /app/sample_attack.pcap

ENTRYPOINT ["netguard_cli"]
CMD ["--pcap", "/app/sample_attack.pcap", "--rules", "/app/config/netguard_rules.json"]
