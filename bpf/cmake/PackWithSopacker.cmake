# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance Inc.

set(CPA_BPF_SOPACKER_DIR "" CACHE PATH "")
set(CPA_BPF_SOPACKER_REPO "https://github.com/XinShuichen/sopacker.git" CACHE STRING "")
set(CPA_BPF_SOPACKER_TAG "main" CACHE STRING "")

if(NOT TARGET cpa)
    message(FATAL_ERROR "PackWithSopacker.cmake requires target cpa")
endif()

if(NOT CPA_BPF_PYTHON)
    cpa_find_required_program(CPA_BPF_PYTHON python3)
endif()
if(NOT CPA_BPF_QUIET_WRAPPER)
    set(CPA_BPF_QUIET_WRAPPER "${CMAKE_SOURCE_DIR}/bpf/tools/quiet_build.py")
endif()

cpa_find_required_program(CPA_BPF_BASH bash)
cpa_find_required_program(CPA_BPF_GIT git)

execute_process(
    COMMAND nproc
    OUTPUT_VARIABLE _cpa_bpf_nproc
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(NOT _cpa_bpf_nproc)
    set(_cpa_bpf_nproc 1)
endif()

set(_cpa_bpf_sopacker_dir "")
if(CPA_BPF_SOPACKER_DIR)
    set(_cpa_bpf_sopacker_dir "${CPA_BPF_SOPACKER_DIR}")
elseif(EXISTS "${CMAKE_SOURCE_DIR}/sopacker/packer")
    set(_cpa_bpf_sopacker_dir "${CMAKE_SOURCE_DIR}/sopacker")
else()
    set(_cpa_bpf_sopacker_dir "${CMAKE_BINARY_DIR}/_deps/sopacker-src")
endif()

if(NOT EXISTS "${_cpa_bpf_sopacker_dir}")
    file(MAKE_DIRECTORY "${_cpa_bpf_sopacker_dir}")
endif()

set(_cpa_bpf_sopacker_checkout_stamp "${CMAKE_BINARY_DIR}/_deps/sopacker.checkout.stamp")
set(_cpa_bpf_sopacker_checkout_log "${CMAKE_BINARY_DIR}/logs/sopacker_checkout.log")
add_custom_command(
    OUTPUT "${_cpa_bpf_sopacker_checkout_stamp}"
    COMMAND
        "${CPA_BPF_PYTHON}"
        "${CPA_BPF_QUIET_WRAPPER}"
        "--tail-lines"
        "0"
        "--show-regex"
        "(^|\\b)(warning:|error:|fatal:|\\*\\*\\*)"
        "--log"
        "${_cpa_bpf_sopacker_checkout_log}"
        "--"
        "${CPA_BPF_BASH}"
        "-lc"
        "set -euo pipefail; if [ -z \"${CPA_BPF_SOPACKER_DIR}\" ] && [ ! -x \"${CMAKE_SOURCE_DIR}/sopacker/packer\" ]; then if [ ! -x \"${_cpa_bpf_sopacker_dir}/packer\" ]; then rm -rf \"${_cpa_bpf_sopacker_dir}\"; \"${CPA_BPF_GIT}\" clone --depth=1 --branch \"${CPA_BPF_SOPACKER_TAG}\" \"${CPA_BPF_SOPACKER_REPO}\" \"${_cpa_bpf_sopacker_dir}\" 2>&1; fi; fi; if [ ! -x \"${_cpa_bpf_sopacker_dir}/packer\" ]; then echo \"fatal: sopacker packer not found under ${_cpa_bpf_sopacker_dir}\"; exit 2; fi; mkdir -p \"${CMAKE_BINARY_DIR}/_deps\"; touch \"${_cpa_bpf_sopacker_checkout_stamp}\""
    VERBATIM
)
add_custom_target(cpa_bpf_sopacker_checkout DEPENDS "${_cpa_bpf_sopacker_checkout_stamp}")

set(_cpa_bpf_patchelf_stamp "${CMAKE_BINARY_DIR}/_deps/sopacker.patchelf.stamp")
set(_cpa_bpf_patchelf_log "${CMAKE_BINARY_DIR}/logs/sopacker_patchelf.log")
add_custom_command(
    OUTPUT "${_cpa_bpf_patchelf_stamp}"
    COMMAND
        "${CPA_BPF_PYTHON}"
        "${CPA_BPF_QUIET_WRAPPER}"
        "--tail-lines"
        "0"
        "--show-regex"
        "(^|\\b)(warning:|error:|fatal:|\\*\\*\\*)"
        "--log"
        "${_cpa_bpf_patchelf_log}"
        "--"
        "${CPA_BPF_BASH}"
        "-lc"
        "set -euo pipefail; cd \"${_cpa_bpf_sopacker_dir}\"; if [ ! -x \"patchelf\" ]; then if [ ! -e \"patchelf_src/.git\" ]; then \"${CPA_BPF_GIT}\" submodule update --init --recursive 2>&1; fi; cd patchelf_src; ./bootstrap.sh; ./configure; make -j${_cpa_bpf_nproc}; cp -f src/patchelf \"${_cpa_bpf_sopacker_dir}/patchelf\"; chmod +x \"${_cpa_bpf_sopacker_dir}/patchelf\"; fi; touch \"${_cpa_bpf_patchelf_stamp}\""
    DEPENDS cpa_bpf_sopacker_checkout
    VERBATIM
)
add_custom_target(cpa_bpf_sopacker_prepare DEPENDS "${_cpa_bpf_patchelf_stamp}")

set(CPA_BPF_PORTABLE_OUTPUT "${CPA_BPF_BIN_DIR}/cpa_portable")
set(_cpa_bpf_portable_tmp_dir "${CPA_BPF_BIN_DIR}/.cpa_portable.tmp")
set(_cpa_bpf_pack_log "${CMAKE_BINARY_DIR}/logs/sopacker_pack.log")
set(_cpa_bpf_pack_script_path "${CMAKE_BINARY_DIR}/_deps/sopacker_pack.sh")
file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/_deps")
file(WRITE "${_cpa_bpf_pack_script_path}" [=[
set -euo pipefail

target="$1"
tmp_dir="$2"
sopacker_dir="$3"
output="$4"

if ldd "$target" 2>&1 | grep -q "not found"; then
    ldd "$target"
    echo "fatal: unresolved dynamic dependency before SOPacker packaging"
    exit 2
fi

rm -rf "$tmp_dir"
mkdir -p "$tmp_dir"
cd "$sopacker_dir"

./packer "$target" "--output=$tmp_dir"
if [ ! -x "$tmp_dir/cpa" ]; then
    echo "fatal: sopacker did not generate $tmp_dir/cpa"
    exit 2
fi

mv -f "$tmp_dir/cpa" "$output"
chmod +x "$output"
]=])

add_custom_command(
    OUTPUT "${CPA_BPF_PORTABLE_OUTPUT}"
    COMMAND
        "${CPA_BPF_PYTHON}"
        "${CPA_BPF_QUIET_WRAPPER}"
        "--tail-lines"
        "0"
        "--show-regex"
        "(^|\\b)(warning:|error:|fatal:|\\*\\*\\*)"
        "--log"
        "${_cpa_bpf_pack_log}"
        "--"
        "${CPA_BPF_BASH}"
        "${_cpa_bpf_pack_script_path}"
        "$<TARGET_FILE:cpa>"
        "${_cpa_bpf_portable_tmp_dir}"
        "${_cpa_bpf_sopacker_dir}"
        "${CPA_BPF_PORTABLE_OUTPUT}"
    BYPRODUCTS
        "${_cpa_bpf_portable_tmp_dir}/cpa"
    DEPENDS
        cpa
        cpa_bpf_sopacker_prepare
    VERBATIM
)

add_custom_target(cpa_portable DEPENDS "${CPA_BPF_PORTABLE_OUTPUT}")
add_dependencies(cpa_portable cpa_bpf_sopacker_prepare)
