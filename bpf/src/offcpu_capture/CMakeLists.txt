# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

cpa_bpf_add_module(offcpu_capture)

# Lite variant for kernels without bpf_get_stack or bounded loops (4.14).
add_bpf_skeleton(
    offcpu_capture_lite_skel
    offcpu_capture_lite_obj
    offcpu_capture_lite
    "${CMAKE_CURRENT_SOURCE_DIR}/offcpu_capture_lite.bpf.c"
    "${CMAKE_CURRENT_SOURCE_DIR}"
)
add_custom_target(cpa_bpf_skel_offcpu_capture_lite DEPENDS "${offcpu_capture_lite_skel}")
add_dependencies(cpa_bpf_skeletons cpa_bpf_skel_offcpu_capture_lite)
set_property(SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/offcpu_capture.c"
             APPEND PROPERTY OBJECT_DEPENDS "${offcpu_capture_lite_skel}")
