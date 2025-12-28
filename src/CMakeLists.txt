# -----------------------------------------------------------------------------
# Automatically discover all source files recursively
# -----------------------------------------------------------------------------
file(GLOB_RECURSE DIA_ALL_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

# Exclude specific files that belong to separate targets
list(FILTER DIA_ALL_SOURCES EXCLUDE REGEX ".*/crypto/ecgroup\\.cpp$")
list(FILTER DIA_ALL_SOURCES EXCLUDE REGEX ".*/bindings/.*\\.cpp$")

# -----------------------------------------------------------------------------
# Cryptographic Shim Library (ecgroup)
# -----------------------------------------------------------------------------
add_library(ecgroup
  crypto/ecgroup.cpp
)

message(STATUS "MCL headers will be pulled from: ${mcl_SOURCE_DIR}/include")
message(STATUS "FetchContent binary dir is: ${CMAKE_BINARY_DIR}/_deps/mcl-src")

target_include_directories(ecgroup
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/crypto>
    $<INSTALL_INTERFACE:include>
    $<BUILD_INTERFACE:${mcl_SOURCE_DIR}/include>
)

target_link_libraries(ecgroup PUBLIC mcl)


# -----------------------------------------------------------------------------
# Main C++ Library (dia)
# -----------------------------------------------------------------------------
add_library(dia
  ${DIA_ALL_SOURCES}
)

target_include_directories(dia
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/crypto>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/protocol>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(dia PUBLIC ecgroup)


# -----------------------------------------------------------------------------
# C Wrapper Library for Bindings
# -----------------------------------------------------------------------------
add_library(dia_c_interface STATIC
  bindings/dia_c.cpp
)

target_include_directories(dia_c_interface
  PRIVATE
    ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(dia_c_interface PUBLIC dia)

if (BUILD_DIA_JNI)
  # -----------------------------------------------------------------------------
  # JNI C++ Library (dia_jni)
  # -----------------------------------------------------------------------------
  # This library should ONLY contain the JNI-specific implementation.
  add_library(dia_jni SHARED
    bindings/dia_jni.cpp
  )

  target_include_directories(dia_jni
    PRIVATE
      # The C header is in the project's include directory
      ${PROJECT_SOURCE_DIR}/include
      # Headers for JNI itself
      ${JNI_INCLUDE_DIRS}
  )

  # Link against the C wrapper library, which in turn links against the core C++ lib.
  # This creates the correct dependency chain: dia_jni -> dia_c_interface -> dia -> mcl
  target_link_libraries(dia_jni
    PRIVATE
      dia_c_interface
  )

  set_target_properties(dia_jni PROPERTIES
    POSITION_INDEPENDENT_CODE ON
  )
endif()
