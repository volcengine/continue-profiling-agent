# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance Inc.

cmake_minimum_required(VERSION 3.10)
project(continue-profiling-agent C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake" "${CMAKE_SOURCE_DIR}/bpf/cmake")
include(CMake310Compat)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

set(CPA_BPF_LLVM_VERSION "15" CACHE STRING "")
set(CPA_BPF_VERSION "1.0.0" CACHE STRING "")

option(CPA_BPF_ENABLE_ASAN "enable asan" OFF)
option(CPA_BPF_QUIET_BUILD "suppress sub-build stdout (show warnings/errors only)" ON)
set(CPA_BPF_BTFHUB_ARCHIVE "${CMAKE_SOURCE_DIR}/bpf/btfhub-archive" CACHE PATH "")

set(CPA_BPF_BIN_DIR "${CMAKE_BINARY_DIR}/bin")
set(CPA_BPF_GEN_DIR "${CMAKE_BINARY_DIR}/generated")
set(CPA_BPF_LIBS_DIR "${CMAKE_BINARY_DIR}/libs")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CPA_BPF_BIN_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CPA_BPF_BIN_DIR}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CPA_BPF_BIN_DIR}")

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    set(CPA_BPF_ARCH "x86")
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
    set(CPA_BPF_ARCH "arm64")
else()
    message(FATAL_ERROR "unsupported arch: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

set(LLVM_BIN "/usr/lib/llvm-${CPA_BPF_LLVM_VERSION}/bin")
cpa_find_required_program(CPA_BPF_CLANG clang HINTS "${LLVM_BIN}")
cpa_find_required_program(CPA_BPF_LLVM_STRIP llvm-strip HINTS "${LLVM_BIN}")
cpa_find_required_program(CPA_BPF_LLVM_OBJDUMP llvm-objdump HINTS "${LLVM_BIN}")
cpa_find_required_program(CPA_BPF_PYTHON python3)
cpa_find_required_program(CPA_BPF_TAR tar)
cpa_find_required_program(CPA_BPF_LD ld)
cpa_find_required_program(CPA_BPF_LD_BFD ld.bfd)

set(CPA_BPF_QUIET_WRAPPER "${CMAKE_SOURCE_DIR}/bpf/tools/quiet_build.py")
if(CPA_BPF_QUIET_BUILD)
    file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/logs")
endif()

function(cpa_bpf_wrap_quiet_command out_var log_name)
    if(CPA_BPF_QUIET_BUILD)
        set(_cmd "${CPA_BPF_PYTHON}" "${CPA_BPF_QUIET_WRAPPER}" "--log" "${CMAKE_BINARY_DIR}/logs/${log_name}.log" "--" ${ARGN})
    else()
        set(_cmd ${ARGN})
    endif()
    set(${out_var} ${_cmd} PARENT_SCOPE)
endfunction()

set(CPA_BPF_INCLUDE_DIRS
    "${CMAKE_SOURCE_DIR}/bpf/include"
    "${CPA_BPF_LIBS_DIR}/libbpf/include"
    "${CMAKE_SOURCE_DIR}/bpf/libbpf/include/uapi"
    "${CMAKE_SOURCE_DIR}/bpf/src/common/include"
    "${CMAKE_SOURCE_DIR}/bpf/vmlinux/${CPA_BPF_ARCH}"
)

file(GLOB CPA_BPF_SRC_DIRS "${CMAKE_SOURCE_DIR}/bpf/src/*")
foreach(dir IN LISTS CPA_BPF_SRC_DIRS)
    if(IS_DIRECTORY "${dir}")
        list(APPEND CPA_BPF_INCLUDE_DIRS "${dir}")
    endif()
endforeach()

set(CPA_BPF_HOST_INCLUDE_DIRS
    "${CMAKE_SOURCE_DIR}"
    "${CMAKE_SOURCE_DIR}/bpf"
    "${CMAKE_SOURCE_DIR}/bpf/include"
    "${CMAKE_SOURCE_DIR}/bpf/src/common/include"
    "${CPA_BPF_LIBS_DIR}/libbpf/include"
    "${CMAKE_SOURCE_DIR}/bpf/libbpf/include"
    "${CMAKE_SOURCE_DIR}/bpf/libbpf/include/uapi"
)
foreach(dir IN LISTS CPA_BPF_SRC_DIRS)
    if(IS_DIRECTORY "${dir}")
        list(APPEND CPA_BPF_HOST_INCLUDE_DIRS "${dir}")
    endif()
endforeach()

include(CpaBpf)

add_library(cpa_bpf_core OBJECT)

target_compile_options(cpa_bpf_core PRIVATE -g -Wall -fPIC)
target_compile_definitions(cpa_bpf_core PRIVATE __CPA_BPF_ARCH_${CPA_BPF_ARCH})
target_include_directories(cpa_bpf_core PRIVATE
    ${CPA_BPF_HOST_INCLUDE_DIRS}
    "${CPA_BPF_GEN_DIR}"
)

if(CPA_BPF_ENABLE_ASAN)
    target_compile_options(cpa_bpf_core PRIVATE -fsanitize=address)
endif()

cpa_bpf_define_deps()
add_dependencies(cpa_bpf_core cpa_bpf_libbpf)

add_subdirectory(bpf/src)
add_dependencies(cpa_bpf_core cpa_bpf_skeletons)

if(EXISTS "${CPA_BPF_BTFHUB_ARCHIVE}")
    cpa_bpf_define_btfgen()
    add_dependencies(cpa_bpf_core cpa_bpf_btfgen)
endif()

include("${CMAKE_SOURCE_DIR}/cmake/cpa.cmake")
include(PackWithSopacker)

add_custom_target(pytest
    COMMAND "${CPA_BPF_PYTHON}" -m pytest -q tests
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    USES_TERMINAL
)
add_dependencies(pytest cpa)

add_custom_target(check DEPENDS pytest)
