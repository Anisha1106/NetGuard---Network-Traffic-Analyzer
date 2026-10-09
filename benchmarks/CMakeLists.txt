add_executable(netguard_benchmarks
    bench_pipeline.cpp
)

target_link_libraries(netguard_benchmarks PRIVATE
    netguard_lib
)
