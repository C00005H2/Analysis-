cmake_minimum_required(VERSION 3.12)
project(minidump
    VERSION 1.0.0
    DESCRIPTION "Portable C++17 Windows minidump file parser library"
    LANGUAGES CXX
)

# Library options (only when building as main project)
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    option(MINIDUMP_BUILD_EXAMPLES "Build example programs" ON)
    option(MINIDUMP_BUILD_TESTS "Build tests" ON)
else()
    option(MINIDUMP_BUILD_EXAMPLES "Build example programs" OFF)
    option(MINIDUMP_BUILD_TESTS "Build tests" OFF)
endif()

# Create the minidump library
add_library(minidump STATIC
    include/minidump/minidump.hpp
    src/minidump.cpp
)

# Add alias for modern CMake usage
add_library(minidump::minidump ALIAS minidump)

# Set C++ standard for this target
target_compile_features(minidump PUBLIC cxx_std_17)

# Configure includes for submodule usage
target_include_directories(minidump PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Set compile options (only for this target)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(minidump PRIVATE -Wall -Wextra -Wpedantic)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    target_compile_options(minidump PRIVATE /W4)
endif()

# Set release optimizations
target_compile_definitions(minidump PRIVATE
    $<$<CONFIG:Release>:NDEBUG>
)

# Examples (only when building as main project)
if(MINIDUMP_BUILD_EXAMPLES)
    add_executable(parse_dump examples/parse_dump.cpp)
    target_link_libraries(parse_dump PRIVATE minidump::minidump)

    add_executable(debug_dump examples/debug_dump.cpp)
    target_link_libraries(debug_dump PRIVATE minidump::minidump)

    add_executable(struct_debug examples/struct_debug.cpp)
    target_link_libraries(struct_debug PRIVATE minidump::minidump)
endif()

# Tests (only when building as main project)
if(MINIDUMP_BUILD_TESTS)
    enable_testing()

    # Define test data paths
    set(TEST_DATA_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../dumps")
    set(TEST_DMP_FILE "${TEST_DATA_DIR}/StringEncryptionFun_x64.dmp")

    # Add basic parsing test
    if(TARGET parse_dump AND EXISTS "${TEST_DMP_FILE}")
        add_test(NAME test_parse_dump
            COMMAND parse_dump "${TEST_DMP_FILE}")
    endif()

    # Custom target for running comparison tests (development only)
    if(TARGET parse_dump)
        add_custom_target(compare
            COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR}/.. && uv run python -m minidump --all ./dumps/StringEncryptionFun_x64.dmp > minidump/python_output.txt
            COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR} && $<TARGET_FILE:parse_dump> ../dumps/StringEncryptionFun_x64.dmp > cpp_output.txt
            COMMAND diff python_output.txt cpp_output.txt || echo "Differences found - checking details..."
            DEPENDS parse_dump
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            COMMENT "Comparing C++ output with Python output"
        )
    endif()
endif()
