# -----------------------------
# Benchmark Executable Definition
# -----------------------------
file(GLOB BENCH_SRC "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
add_executable(run_dia_benchmarks ${BENCH_SRC})
target_include_directories(run_dia_benchmarks PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")

# -----------------------------------------------------------------------------
# Link Libraries
# -----------------------------------------------------------------------------
target_link_libraries(run_dia_benchmarks PRIVATE dia mcl)
