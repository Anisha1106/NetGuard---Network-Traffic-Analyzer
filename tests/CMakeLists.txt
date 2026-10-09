enable_testing()

include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(netguard_tests
    test_bounded_queue.cpp
    test_packet_parser.cpp
    test_flow_tracker.cpp
    test_detectors.cpp
    test_pipeline.cpp
)

target_link_libraries(netguard_tests PRIVATE
    netguard_lib
    GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(netguard_tests)
