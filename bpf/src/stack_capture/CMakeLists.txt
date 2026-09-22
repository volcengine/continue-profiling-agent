# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

cpa_bpf_add_module(stack_capture)

# Ring buffer datapath variant: a separate BPF object whose programs emit to
# events_rb instead of perf_output_events. Userspace selects the variant at
# setup time and falls back to the perf-buffer skeleton when unsupported.
add_bpf_skeleton(
    stack_capture_ringbuf_skel
    stack_capture_ringbuf_obj
    stack_capture_ringbuf
    "${CMAKE_CURRENT_SOURCE_DIR}/stack_capture_ringbuf.bpf.c"
    "${CMAKE_CURRENT_SOURCE_DIR}"
)
add_custom_target(cpa_bpf_skel_stack_capture_ringbuf DEPENDS "${stack_capture_ringbuf_skel}")
add_dependencies(cpa_bpf_skeletons cpa_bpf_skel_stack_capture_ringbuf)

# The host loader includes both generated skeletons.
set_property(SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/stack_capture.c"
             APPEND PROPERTY OBJECT_DEPENDS "${stack_capture_ringbuf_skel}")
