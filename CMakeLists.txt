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
project(dia VERSION 2.0.3 LANGUAGES C CXX)

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

# -----------------------------------------------------------------------------
# libsodium: Use system version if available, otherwise fetch and build
# -----------------------------------------------------------------------------
option(FORCE_BUNDLED_SODIUM "Force building libsodium from source" OFF)

set(SODIUM_FOUND_SYSTEM FALSE)

if(NOT FORCE_BUNDLED_SODIUM)
  # Try to find system libsodium
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(SODIUM QUIET libsodium)
    if(SODIUM_FOUND)
      set(SODIUM_FOUND_SYSTEM TRUE)
      message(STATUS "Found system libsodium: ${SODIUM_LIBRARIES}")
      message(STATUS "  Library dirs: ${SODIUM_LIBRARY_DIRS}")
      message(STATUS "  Include dirs: ${SODIUM_INCLUDE_DIRS}")
      # For static linking, we need the library directory
      if(SODIUM_LIBRARY_DIRS)
        set(SODIUM_LIBDIR ${SODIUM_LIBRARY_DIRS})
      else()
        # Fallback: query pkg-config for libdir
        execute_process(
          COMMAND ${PKG_CONFIG_EXECUTABLE} --variable=libdir libsodium
          OUTPUT_VARIABLE SODIUM_LIBDIR
          OUTPUT_STRIP_TRAILING_WHITESPACE
        )
      endif()
      # Use static library for embedding
      find_library(SODIUM_STATIC_LIB libsodium.a HINTS ${SODIUM_LIBDIR} ${SODIUM_LIBRARY_DIRS})
      if(SODIUM_STATIC_LIB)
        set(SODIUM_LIBRARIES ${SODIUM_STATIC_LIB})
        message(STATUS "  Using static libsodium: ${SODIUM_LIBRARIES}")
      endif()
    endif()
  endif()
endif()

if(NOT SODIUM_FOUND_SYSTEM)
  message(STATUS "System libsodium not found or FORCE_BUNDLED_SODIUM=ON → building from source")
  
  # libsodium stable release
  set(SODIUM_VERSION "1.0.20")
  set(SODIUM_URL "https://github.com/jedisct1/libsodium/releases/download/${SODIUM_VERSION}-RELEASE/libsodium-${SODIUM_VERSION}.tar.gz")
  
  FetchContent_Declare(
    sodium
    URL ${SODIUM_URL}
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  )
  FetchContent_GetProperties(sodium)
  if(NOT sodium_POPULATED)
    FetchContent_Populate(sodium)
    
    set(SODIUM_SOURCE_DIR ${sodium_SOURCE_DIR})
    set(SODIUM_BINARY_DIR ${sodium_BINARY_DIR})
    
    # Build libsodium using autotools or cmake
    if(ANDROID)
      # Android cross-compilation
      message(STATUS "Building libsodium for Android: ${ANDROID_ABI}")
      
      # Determine the host triple for Android
      if(ANDROID_ABI STREQUAL "arm64-v8a")
        set(SODIUM_HOST "aarch64-linux-android")
        set(SODIUM_COMPILER_PREFIX "aarch64-linux-android")
      elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
        set(SODIUM_HOST "armv7a-linux-androideabi")
        set(SODIUM_COMPILER_PREFIX "armv7a-linux-androideabi")
      elseif(ANDROID_ABI STREQUAL "x86_64")
        set(SODIUM_HOST "x86_64-linux-android")
        set(SODIUM_COMPILER_PREFIX "x86_64-linux-android")
      elseif(ANDROID_ABI STREQUAL "x86")
        set(SODIUM_HOST "i686-linux-android")
        set(SODIUM_COMPILER_PREFIX "i686-linux-android")
      else()
        message(FATAL_ERROR "Unsupported Android ABI: ${ANDROID_ABI}")
      endif()
      
      # Set up Android NDK environment variables
      # Use the NDK's target-specific compiler wrappers
      # Find ANDROID_NDK path (can be ANDROID_NDK, ANDROID_NDK_ROOT, or ANDROID_NDK_HOME)
      if(NOT ANDROID_NDK)
        if(DEFINED ENV{ANDROID_NDK})
          set(ANDROID_NDK $ENV{ANDROID_NDK})
        elseif(DEFINED ENV{ANDROID_NDK_ROOT})
          set(ANDROID_NDK $ENV{ANDROID_NDK_ROOT})
        elseif(DEFINED ENV{ANDROID_NDK_HOME})
          set(ANDROID_NDK $ENV{ANDROID_NDK_HOME})
        else()
          message(FATAL_ERROR "ANDROID_NDK not found. Set ANDROID_NDK, ANDROID_NDK_ROOT, or ANDROID_NDK_HOME")
        endif()
      endif()
      
      # Detect the host system for NDK prebuilt directory
      if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
        set(ANDROID_HOST_TAG "linux-x86_64")
      elseif(CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin")
        set(ANDROID_HOST_TAG "darwin-x86_64")
      elseif(CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
        set(ANDROID_HOST_TAG "windows-x86_64")
      else()
        message(FATAL_ERROR "Unsupported host system: ${CMAKE_HOST_SYSTEM_NAME}")
      endif()
      
      # Extract API level from ANDROID_PLATFORM (e.g., "android-24" -> "24")
      string(REGEX REPLACE "android-" "" ANDROID_API_LEVEL "${ANDROID_PLATFORM}")
      
      find_program(SODIUM_CC 
        NAMES ${SODIUM_COMPILER_PREFIX}${ANDROID_API_LEVEL}-clang
        PATHS ${ANDROID_NDK}/toolchains/llvm/prebuilt/${ANDROID_HOST_TAG}/bin
        NO_DEFAULT_PATH
      )
      find_program(SODIUM_AR 
        NAMES llvm-ar
        PATHS ${ANDROID_NDK}/toolchains/llvm/prebuilt/${ANDROID_HOST_TAG}/bin
        NO_DEFAULT_PATH
      )
      find_program(SODIUM_RANLIB 
        NAMES llvm-ranlib
        PATHS ${ANDROID_NDK}/toolchains/llvm/prebuilt/${ANDROID_HOST_TAG}/bin
        NO_DEFAULT_PATH
      )
      
      if(NOT SODIUM_CC)
        message(FATAL_ERROR "Could not find Android C compiler for ${ANDROID_ABI}")
      endif()
      
      message(STATUS "libsodium Android build:")
      message(STATUS "  CC: ${SODIUM_CC}")
      message(STATUS "  AR: ${SODIUM_AR}")
      message(STATUS "  RANLIB: ${SODIUM_RANLIB}")
      message(STATUS "  HOST: ${SODIUM_HOST}")
      
      set(SODIUM_INSTALL_DIR ${SODIUM_BINARY_DIR}/install)
      file(MAKE_DIRECTORY ${SODIUM_INSTALL_DIR})
      
      execute_process(
        COMMAND ${CMAKE_COMMAND} -E env
          CC=${SODIUM_CC}
          AR=${SODIUM_AR}
          RANLIB=${SODIUM_RANLIB}
          CFLAGS=${CMAKE_C_FLAGS}
          ${SODIUM_SOURCE_DIR}/configure
            --prefix=${SODIUM_INSTALL_DIR}
            --host=${SODIUM_HOST}
            --disable-shared
            --enable-static
            --disable-pie
        WORKING_DIRECTORY ${SODIUM_BINARY_DIR}
        RESULT_VARIABLE SODIUM_CONFIGURE_RESULT
      )
      if(NOT SODIUM_CONFIGURE_RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to configure libsodium for Android")
      endif()
      
      execute_process(
        COMMAND make -j4
        WORKING_DIRECTORY ${SODIUM_BINARY_DIR}
        RESULT_VARIABLE SODIUM_BUILD_RESULT
      )
      if(NOT SODIUM_BUILD_RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to build libsodium for Android")
      endif()
      
      execute_process(
        COMMAND make install
        WORKING_DIRECTORY ${SODIUM_BINARY_DIR}
        RESULT_VARIABLE SODIUM_INSTALL_RESULT
      )
      if(NOT SODIUM_INSTALL_RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to install libsodium for Android")
      endif()
      
      set(SODIUM_INCLUDE_DIRS ${SODIUM_INSTALL_DIR}/include)
      set(SODIUM_LIBRARIES ${SODIUM_INSTALL_DIR}/lib/libsodium.a)
      
    elseif(WIN32)
      # Windows: use CMake-based build if available, or prebuilt binaries
      message(STATUS "Building libsodium for Windows")
      # libsodium has CMake support in builds/cmake
      add_subdirectory(${SODIUM_SOURCE_DIR}/builds/cmake ${SODIUM_BINARY_DIR} EXCLUDE_FROM_ALL)
      set(SODIUM_INCLUDE_DIRS ${SODIUM_SOURCE_DIR}/src/libsodium/include)
      set(SODIUM_LIBRARIES sodium)
      
    else()
      # Unix-like systems (Linux, macOS)
      message(STATUS "Building libsodium from source using autotools")
      
      set(SODIUM_INSTALL_DIR ${SODIUM_BINARY_DIR}/install)
      file(MAKE_DIRECTORY ${SODIUM_INSTALL_DIR})
      
      # Configure
      execute_process(
        COMMAND ${SODIUM_SOURCE_DIR}/configure
          --prefix=${SODIUM_INSTALL_DIR}
          --disable-shared
          --enable-static
          --with-pic
        WORKING_DIRECTORY ${SODIUM_BINARY_DIR}
        RESULT_VARIABLE SODIUM_CONFIGURE_RESULT
      )
      if(NOT SODIUM_CONFIGURE_RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to configure libsodium")
      endif()
      
      # Build
      include(ProcessorCount)
      ProcessorCount(NPROC)
      if(NOT NPROC)
        set(NPROC 1)
      endif()
      
      execute_process(
        COMMAND make -j${NPROC}
        WORKING_DIRECTORY ${SODIUM_BINARY_DIR}
        RESULT_VARIABLE SODIUM_BUILD_RESULT
      )
      if(NOT SODIUM_BUILD_RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to build libsodium")
      endif()
      
      # Install locally
      execute_process(
        COMMAND make install
        WORKING_DIRECTORY ${SODIUM_BINARY_DIR}
        RESULT_VARIABLE SODIUM_INSTALL_RESULT
      )
      if(NOT SODIUM_INSTALL_RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to install libsodium")
      endif()
      
      set(SODIUM_INCLUDE_DIRS ${SODIUM_INSTALL_DIR}/include)
      set(SODIUM_LIBRARIES ${SODIUM_INSTALL_DIR}/lib/libsodium.a)
    endif()
  endif()
  
  message(STATUS "Using bundled libsodium: ${SODIUM_LIBRARIES}")
endif()

# Export sodium variables for use in subdirectories
set(SODIUM_INCLUDE_DIRS ${SODIUM_INCLUDE_DIRS} CACHE INTERNAL "libsodium include dirs")
set(SODIUM_LIBRARIES ${SODIUM_LIBRARIES} CACHE INTERNAL "libsodium libraries")

# Set pkg-config variables for sodium
if(SODIUM_FOUND_SYSTEM)
  # System libsodium - just reference it
  set(SODIUM_PKG_LIBS "-lsodium")
  if(SODIUM_INCLUDE_DIRS)
    set(SODIUM_PKG_CFLAGS "-I${SODIUM_INCLUDE_DIRS}")
  else()
    set(SODIUM_PKG_CFLAGS "")
  endif()
else()
  # Bundled sodium will be installed alongside libdia
  set(SODIUM_PKG_LIBS "-lsodium")
  set(SODIUM_PKG_CFLAGS "")
endif()

message(STATUS "SODIUM_PKG_LIBS: [${SODIUM_PKG_LIBS}]")
message(STATUS "SODIUM_PKG_CFLAGS: [${SODIUM_PKG_CFLAGS}]")

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

# Install bundled libsodium if it was built from source
if(NOT SODIUM_FOUND_SYSTEM AND SODIUM_LIBRARIES)
  get_filename_component(SODIUM_LIB_FILE "${SODIUM_LIBRARIES}" NAME)
  install(FILES "${SODIUM_LIBRARIES}"
          DESTINATION lib)
  # Also install headers if available
  if(SODIUM_INCLUDE_DIRS)
    install(DIRECTORY "${SODIUM_INCLUDE_DIRS}/"
            DESTINATION include
            FILES_MATCHING PATTERN "*.h")
  endif()
endif()

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
 # Development pkg-config file (for use without installing)
 configure_file(
   ${CMAKE_SOURCE_DIR}/dia-dev.pc.in
   ${CMAKE_BINARY_DIR}/dia-dev.pc
   @ONLY
 )
 install(
   FILES ${CMAKE_BINARY_DIR}/dia.pc
   DESTINATION lib/pkgconfig
 )
endif()
