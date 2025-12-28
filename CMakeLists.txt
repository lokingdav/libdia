# CMake minimum version required
cmake_minimum_required(VERSION 3.22 FATAL_ERROR)

# Force MCL to compile with no .param file and only static linkage
set(MCL_USE_PARAM_FILE   OFF CACHE BOOL "" FORCE)
set(MCL_BUILD_SHARED     OFF CACHE BOOL "" FORCE)
set(MCL_BUILD_STATIC     ON  CACHE BOOL "" FORCE)

# -----------------------------------------------------------------------------
# Project Definition
# -----------------------------------------------------------------------------
# Define the project name, version, and language
project(dia VERSION 1.0.0 LANGUAGES C CXX)

# -----------------------------------------------------------------------------
# C++ Standard Configuration
# -----------------------------------------------------------------------------
# Set the C++ standard to C++17. This ensures that modern language features
# are available. The 'REQUIRED' keyword means CMake will fail if the compiler
# doesn't support C++17.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

message(STATUS "Building dia Version: ${PROJECT_VERSION}")

# -----------------------------------------------------------------------------
# Build Options
# -----------------------------------------------------------------------------
option(BUILD_DIA_TESTING "Build the tests" ON)
option(BUILD_DIA_BENCHMARK "Build the benchmarks" ON)
option(BUILD_DIA_JNI "Build for Android" OFF)

message(STATUS "BUILD_DIA_TESTING: ${BUILD_DIA_TESTING}")
message(STATUS "BUILD_DIA_BENCHMARK: ${BUILD_DIA_BENCHMARK}")
message(STATUS "BUILD_DIA_JNI: ${BUILD_DIA_JNI}")

# Make all targets (static and shared) position‐independent by default
set(CMAKE_POSITION_INDEPENDENT_CODE ON)


# -----------------------------------------------------------------------------
# Dependencies
# -----------------------------------------------------------------------------
include(FetchContent)

# Decide which MCL to fetch:
set(MCL_GIT_REPO  "https://github.com/herumi/mcl.git")
set(MCL_GIT_TAG   "v3.00")

# When cross-compiling for Android (or ANDROID is defined), switch to your fork:
if(CMAKE_CROSSCOMPILING OR ANDROID)
  message(STATUS "Android build detected → using forked MCL with Android patch")
  set(MCL_GIT_REPO  "https://github.com/lokingdav/mcl-patch.git")
  set(MCL_GIT_TAG   "ba95939")
endif()

message("MCL will be cloned from URL=${MCL_GIT_REPO},  TAG=${MCL_GIT_TAG}")

# Declare and fetch the MCL dependency automatically
FetchContent_Declare(
  mcl
  GIT_REPOSITORY ${MCL_GIT_REPO}
  GIT_TAG        ${MCL_GIT_TAG}
)
FetchContent_MakeAvailable(mcl)

# Find libsodium (must be installed on the system)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# -----------------------------------------------------------------------------
# Subdirectory Processing
# -----------------------------------------------------------------------------
add_subdirectory(src)

if(BUILD_DIA_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()

if(BUILD_DIA_BENCHMARK)
  add_subdirectory(benchmarks)
endif()

# -----------------------------------------------------------------------------
# Installation Rules (all libraries in one shot)
# -----------------------------------------------------------------------------
install(TARGETS
  ecgroup
  dia
  dia_c_interface
  ARCHIVE  DESTINATION lib
  LIBRARY  DESTINATION lib
  RUNTIME  DESTINATION bin
)

 # Install the public header files.
 install(DIRECTORY include/
         DESTINATION include)

if (NOT ANDROID)
 # Install pkg-config file
 configure_file(
   ${CMAKE_SOURCE_DIR}/dia.pc.in
   ${CMAKE_BINARY_DIR}/dia.pc
   @ONLY
 )
 install(
   FILES ${CMAKE_BINARY_DIR}/dia.pc
   DESTINATION lib/pkgconfig
 )
endif()
