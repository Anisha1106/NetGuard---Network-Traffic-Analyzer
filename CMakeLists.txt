cmake_minimum_required(VERSION 3.20)
project(netguard_cpp VERSION 1.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler Flags & Optimization
if(MSVC)
    add_compile_options(/W4 /permissive-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -O3)
endif()

# Sanitizer Options for Debugging
option(SANITIZE_ADDRESS "Enable AddressSanitizer" OFF)
option(SANITIZE_THREAD "Enable ThreadSanitizer" OFF)
option(SANITIZE_UNDEFINED "Enable UndefinedBehaviorSanitizer" OFF)

if(SANITIZE_ADDRESS)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
endif()

if(SANITIZE_THREAD)
    add_compile_options(-fsanitize=thread)
    add_link_options(-fsanitize=thread)
endif()

if(SANITIZE_UNDEFINED)
    add_compile_options(-fsanitize=undefined)
    add_link_options(-fsanitize=undefined)
endif()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Library Sources
set(NETGUARD_LIB_SOURCES
    src/core/types.cpp
    src/core/packet.cpp
    src/core/alert.cpp
    src/parser/packet_parser.cpp
    src/parser/pcap_reader.cpp
    src/pipeline/flow_tracker.cpp
    src/pipeline/processing_pipeline.cpp
    src/ids/rule_config.cpp
    src/ids/port_scan_detector.cpp
    src/ids/traffic_spike_detector.cpp
    src/ids/connection_spike_detector.cpp
    src/ids/anomaly_detector.cpp
    src/reporting/json_reporter.cpp
    src/reporting/csv_reporter.cpp
    src/reporting/console_reporter.cpp
    src/utils/logger.cpp
)

add_library(netguard_lib STATIC ${NETGUARD_LIB_SOURCES})

# Target Include Directories
target_include_directories(netguard_lib PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# CLI Executable
add_executable(netguard_cli src/main.cpp)
target_link_libraries(netguard_cli PRIVATE netguard_lib)

# Sample PCAP Generator Executable
add_executable(netguard_sample_gen samples/pcap_generator.cpp)
target_link_libraries(netguard_sample_gen PRIVATE netguard_lib)

# Testing & Benchmarking Subdirectories
option(BUILD_TESTS "Build GoogleTest Unit and Integration Tests" ON)
option(BUILD_BENCHMARKS "Build Performance Benchmarks" ON)

if(BUILD_TESTS)
    add_subdirectory(tests)
endif()

if(BUILD_BENCHMARKS)
    add_subdirectory(benchmarks)
endif()
