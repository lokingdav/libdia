# -----------------------------------------------------------------------------
# Test Framework Installation
# -----------------------------------------------------------------------------
FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v3.4.0
)
FetchContent_MakeAvailable(Catch2)


# -----------------------------
# Test Executable Definition (using Catch2)
# -----------------------------
file(GLOB TEST_SRC_FILES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
add_executable(run_dia_tests ${TEST_SRC_FILES})
target_include_directories(run_dia_tests PRIVATE "${PROJECT_SOURCE_DIR}/src")

# -----------------------------------------------------------------------------
# Link Libraries
# -----------------------------------------------------------------------------
target_link_libraries(run_dia_tests PRIVATE dia Catch2::Catch2WithMain mcl)
