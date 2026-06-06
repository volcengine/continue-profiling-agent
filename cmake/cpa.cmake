# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance Inc.

set(CPA_ROOT "${CMAKE_SOURCE_DIR}")
set(CPA_SRC_DIR "${CPA_ROOT}/src")

if(NOT DEFINED CPA_BPF_GEN_DIR)
    set(CPA_BPF_GEN_DIR "${CMAKE_BINARY_DIR}/generated")
endif()

set(CPA_GEN_DIR "${CPA_BPF_GEN_DIR}/cpa")
file(MAKE_DIRECTORY "${CPA_GEN_DIR}/auto")

function(cpa_find_required_library out_name)
    cmake_parse_arguments(ARG "" "NAME" "NAMES" ${ARGN})
    if(NOT ARG_NAME)
        message(FATAL_ERROR "cpa_find_required_library missing NAME")
    endif()
    if(ARG_NAMES)
        set(_cpa_names ${ARG_NAMES})
    else()
        set(_cpa_names ${ARG_NAME})
    endif()
    find_library(
        ${out_name}
        NAMES ${_cpa_names}
        PATH_SUFFIXES
            "${CMAKE_LIBRARY_ARCHITECTURE}"
            "x86_64-linux-gnu"
            "aarch64-linux-gnu"
            "arm64-linux-gnu"
    )
    if(NOT ${out_name})
        message(
            FATAL_ERROR
            "required library not found: ${ARG_NAME}. "
            "CMAKE_LIBRARY_ARCHITECTURE='${CMAKE_LIBRARY_ARCHITECTURE}'. "
            "Try -DCMAKE_FIND_DEBUG_MODE=ON or set -DCMAKE_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu."
        )
    endif()
    set(${out_name} "${${out_name}}" PARENT_SCOPE)
endfunction()

set(CPA_COMMON_DIRS
    cli_zstd_helper
    cli_config_helper
    cli_queue_helper
    cli_stackmap_helper
    cli_dir_manager
    cli_profile_metadata
    cli_struct_helper
    cli_counter_helper
)

set(CPA_EXTRA_COMMON_SOURCES
)

set(CPA_MODULE_DIRS
    cpa_monitor
    cpa_show
)

set(CPA_MONITOR_SOURCES
    "${CPA_SRC_DIR}/cpa_monitor/cpa_capture_mode.c"
    "${CPA_SRC_DIR}/cpa_monitor/cpa_backend_preflight.c"
    "${CPA_SRC_DIR}/cpa_monitor/cpa_monitor.c"
    "${CPA_SRC_DIR}/cpa_monitor/cpa_runtime.c"
    "${CPA_SRC_DIR}/cpa_monitor/cpa_bpf_capture.c"
    "${CPA_SRC_DIR}/cpa_monitor/cpa_perf_capture.c"
    "${CPA_SRC_DIR}/cpa_monitor/cpa_unwinder.c"
    "${CPA_SRC_DIR}/cpa_monitor/cpa_env.c"
    "${CPA_SRC_DIR}/cpa_monitor/cpa_nobpf_unwinder_event.c"
    "${CPA_SRC_DIR}/cpa_monitor/cpa_stackmap_continuous.c"
    "${CPA_SRC_DIR}/cpa_monitor/cpa_stackmap_oneshot.c"
    "${CPA_SRC_DIR}/cpa_monitor/cpa_stat.c"
    "${CPA_SRC_DIR}/cpa_monitor/cpa_debug.c"
    "${CPA_SRC_DIR}/cpa_monitor/cpa_drop_policy.c"
)

set(CPA_WORKER_C_FILES
    "${CPA_SRC_DIR}/cpa_monitor/cpa_bpf_capture.c"
    "${CPA_SRC_DIR}/cpa_monitor/cpa_perf_capture.c"
    "${CPA_SRC_DIR}/cpa_monitor/cpa_unwinder.c"
    "${CPA_SRC_DIR}/cpa_monitor/cpa_env.c"
    "${CPA_SRC_DIR}/cpa_monitor/cpa_nobpf_unwinder_event.c"
    "${CPA_SRC_DIR}/cpa_monitor/cpa_stackmap_continuous.c"
    "${CPA_SRC_DIR}/cpa_monitor/cpa_stackmap_oneshot.c"
    "${CPA_SRC_DIR}/cpa_monitor/cpa_stat.c"
    "${CPA_SRC_DIR}/cpa_monitor/cpa_debug.c"
)

set(CPA_SOURCES
    "${CPA_SRC_DIR}/cli.c"
    "${CPA_SRC_DIR}/cli_cmd_helper.c"
    "${CPA_SRC_DIR}/cli_common.c"
    "${CPA_SRC_DIR}/cli_output.c"
)

set(CPA_INCLUDE_DIRS "${CPA_SRC_DIR}")

foreach(d IN LISTS CPA_COMMON_DIRS)
    file(GLOB c_files "${CPA_SRC_DIR}/${d}/*.c")
    list(APPEND CPA_SOURCES ${c_files})
    list(APPEND CPA_INCLUDE_DIRS "${CPA_SRC_DIR}/${d}")
endforeach()

list(APPEND CPA_SOURCES ${CPA_EXTRA_COMMON_SOURCES})
list(APPEND CPA_INCLUDE_DIRS "${CPA_SRC_DIR}/cli_profile_cui_helper")

list(APPEND CPA_SOURCES ${CPA_MONITOR_SOURCES})
list(APPEND CPA_SOURCES "${CPA_SRC_DIR}/cpa_show/cpa_show.c")
list(APPEND CPA_INCLUDE_DIRS "${CPA_SRC_DIR}/cpa_monitor")
list(APPEND CPA_INCLUDE_DIRS "${CPA_SRC_DIR}/cpa_show")

set(CPA_GEN_MODULES_H "${CPA_GEN_DIR}/auto/gen_modules.h")
file(WRITE "${CPA_GEN_MODULES_H}" "")
foreach(m IN LISTS CPA_MODULE_DIRS)
    file(APPEND "${CPA_GEN_MODULES_H}" "DEFINE_SUB_CMD(${m})\n")
endforeach()

set(CPA_WORKERS_H "${CPA_GEN_DIR}/cpa_workers.h")
add_custom_command(
    OUTPUT "${CPA_WORKERS_H}"
    COMMAND "${CPA_BPF_PYTHON}"
        "${CPA_SRC_DIR}/cpa_monitor/extract_cpa_workers.py"
        "${CPA_WORKERS_H}"
        ${CPA_WORKER_C_FILES}
    DEPENDS
        ${CPA_WORKER_C_FILES}
        "${CPA_SRC_DIR}/cpa_monitor/extract_cpa_workers.py"
    WORKING_DIRECTORY "${CPA_SRC_DIR}/cpa_monitor"
)
add_custom_target(cpa_generate_workers DEPENDS "${CPA_WORKERS_H}")

set(CPA_GUNWINDER_PATH "${CPA_ROOT}/libs/libgunwinder")
set(CPA_GUNWINDER_INCLUDE_DIR "${CPA_GUNWINDER_PATH}/include")
set(CPA_GUNWINDER_SOURCE_LIBRARY "${CPA_GUNWINDER_PATH}/lib/libgunwinder.so")
set(
    CPA_GUNWINDER_SOURCE_LIBRARY_SONAME
    "${CPA_GUNWINDER_PATH}/lib/libgunwinder.so.1"
)
set(
    CPA_GUNWINDER_SOURCE_LIBRARY_REAL
    "${CPA_GUNWINDER_PATH}/lib/libgunwinder.so.1.0.0"
)
set(CPA_GUNWINDER_RUNTIME_LIBRARY "${CPA_BPF_BIN_DIR}/libgunwinder.so")
set(
    CPA_GUNWINDER_RUNTIME_LIBRARY_SONAME
    "${CPA_BPF_BIN_DIR}/libgunwinder.so.1"
)
set(
    CPA_GUNWINDER_RUNTIME_LIBRARY_REAL
    "${CPA_BPF_BIN_DIR}/libgunwinder.so.1.0.0"
)
if(NOT IS_DIRECTORY "${CPA_GUNWINDER_PATH}")
    message(FATAL_ERROR "vendored libgunwinder source directory not found: ${CPA_GUNWINDER_PATH}")
endif()

file(GLOB_RECURSE CPA_GUNWINDER_SOURCES
    "${CPA_GUNWINDER_PATH}/include/*.h"
    "${CPA_GUNWINDER_PATH}/src/*.c"
    "${CPA_GUNWINDER_PATH}/src/*.h"
)
list(APPEND CPA_GUNWINDER_SOURCES "${CPA_GUNWINDER_PATH}/Makefile")

set(CPA_GUNWINDER_DEBUG_FLAGS "-g")
if(CPA_BPF_ENABLE_ASAN)
    set(CPA_GUNWINDER_DEBUG_FLAGS "-g -fsanitize=address")
endif()

cpa_bpf_wrap_quiet_command(
    cpa_gunwinder_build_cmd
    "cpa_gunwinder_build"
    make
    "CC=${CMAKE_C_COMPILER}"
    "AR=${CMAKE_AR}"
    "DEBUG_FLAGS=${CPA_GUNWINDER_DEBUG_FLAGS}"
    "lib/libgunwinder.so"
)
add_custom_command(
    OUTPUT
        "${CPA_GUNWINDER_SOURCE_LIBRARY}"
        "${CPA_GUNWINDER_SOURCE_LIBRARY_SONAME}"
        "${CPA_GUNWINDER_SOURCE_LIBRARY_REAL}"
    COMMAND ${cpa_gunwinder_build_cmd}
    WORKING_DIRECTORY "${CPA_GUNWINDER_PATH}"
    DEPENDS ${CPA_GUNWINDER_SOURCES}
    VERBATIM
)
add_custom_command(
    OUTPUT
        "${CPA_GUNWINDER_RUNTIME_LIBRARY}"
        "${CPA_GUNWINDER_RUNTIME_LIBRARY_SONAME}"
        "${CPA_GUNWINDER_RUNTIME_LIBRARY_REAL}"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
        "${CPA_GUNWINDER_SOURCE_LIBRARY_REAL}"
        "${CPA_GUNWINDER_RUNTIME_LIBRARY_REAL}"
    COMMAND "${CMAKE_COMMAND}" -E create_symlink
        "libgunwinder.so.1.0.0"
        "${CPA_GUNWINDER_RUNTIME_LIBRARY_SONAME}"
    COMMAND "${CMAKE_COMMAND}" -E create_symlink
        "libgunwinder.so.1"
        "${CPA_GUNWINDER_RUNTIME_LIBRARY}"
    DEPENDS
        "${CPA_GUNWINDER_SOURCE_LIBRARY}"
        "${CPA_GUNWINDER_SOURCE_LIBRARY_SONAME}"
        "${CPA_GUNWINDER_SOURCE_LIBRARY_REAL}"
    VERBATIM
)
add_custom_target(cpa_gunwinder_build DEPENDS "${CPA_GUNWINDER_RUNTIME_LIBRARY}")

add_library(cpa_gunwinder SHARED IMPORTED GLOBAL)
set_target_properties(cpa_gunwinder PROPERTIES IMPORTED_LOCATION "${CPA_GUNWINDER_RUNTIME_LIBRARY}")
target_include_directories(cpa_gunwinder INTERFACE "${CPA_GUNWINDER_INCLUDE_DIR}")
add_dependencies(cpa_gunwinder cpa_gunwinder_build)

cpa_find_required_library(CPA_LIBDW NAME dw)
cpa_find_required_library(CPA_LIBELF NAME elf)
cpa_find_required_library(CPA_LIBZSTD NAME zstd)
cpa_find_required_library(CPA_LIBCRYPTO NAME crypto)
cpa_find_required_library(CPA_LIBIBERTY NAME iberty)

find_program(CPA_CARGO cargo)
if(NOT CPA_CARGO)
    message(FATAL_ERROR "cargo not found; cpa_show is required for cpa")
endif()

set(CPA_SHOW_RUST_DIR "${CPA_SRC_DIR}/cpa_show/rust")
set(CPA_SHOW_RUST_LIB "${CPA_SHOW_RUST_DIR}/target/release/libcpa_show.a")
file(GLOB_RECURSE CPA_SHOW_RUST_RS "${CPA_SHOW_RUST_DIR}/src/*.rs")
set(CPA_SHOW_RUST_DEPENDS
    "${CPA_SHOW_RUST_DIR}/Cargo.toml"
    "${CPA_SHOW_RUST_DIR}/Cargo.lock"
    "${CPA_SHOW_RUST_DIR}/build.rs"
    ${CPA_SHOW_RUST_RS}
)
add_custom_command(
    OUTPUT "${CPA_SHOW_RUST_LIB}"
    COMMAND "${CPA_CARGO}" build --release --lib
    WORKING_DIRECTORY "${CPA_SHOW_RUST_DIR}"
    DEPENDS ${CPA_SHOW_RUST_DEPENDS}
    VERBATIM
)
add_custom_target(cpa_show_rust_build DEPENDS "${CPA_SHOW_RUST_LIB}")

add_executable(cpa ${CPA_SOURCES})
add_dependencies(cpa cpa_generate_workers cpa_show_rust_build)
target_sources(cpa PRIVATE $<TARGET_OBJECTS:cpa_bpf_core>)
set_target_properties(cpa PROPERTIES
    BUILD_WITH_INSTALL_RPATH TRUE
    INSTALL_RPATH "$ORIGIN"
)

target_include_directories(cpa PRIVATE
    ${CPA_INCLUDE_DIRS}
    "${CPA_GEN_DIR}"
    ${CPA_BPF_HOST_INCLUDE_DIRS}
)
target_include_directories(cpa PRIVATE "${CPA_SRC_DIR}/cpa_show/include")
target_compile_definitions(cpa PRIVATE CPA_ENABLE_CPA_SHOW=1)

target_compile_definitions(cpa PRIVATE
    CLI_VERSION="${CPA_BPF_VERSION}"
    __CPA_BPF_ARCH_${CPA_BPF_ARCH}
)

if(CPA_BPF_ENABLE_ASAN)
    target_compile_options(cpa PRIVATE -fsanitize=address)
    if(COMMAND target_link_options)
        target_link_options(cpa PRIVATE -fsanitize=address)
    else()
        set_property(
            TARGET cpa
            APPEND_STRING
            PROPERTY LINK_FLAGS " -fsanitize=address"
        )
    endif()
endif()

target_link_libraries(cpa PRIVATE
    "${CPA_BPF_LIBBPF_A}"
    cpa_gunwinder
    "${CPA_SHOW_RUST_LIB}"
    ${CPA_LIBDW}
    ${CPA_LIBELF}
    ${CPA_LIBZSTD}
    ${CPA_LIBCRYPTO}
    ${CPA_LIBIBERTY}
    dl
    m
    z
    pthread
    rt
)

add_dependencies(cpa
    cpa_bpf_core
    cpa_bpf_libbpf
    cpa_bpf_bpftool
    cpa_gunwinder_build
)
