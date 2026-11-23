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

# Lite variant for kernels without bpf_get_stack or bounded loops (4.14).
add_bpf_skeleton(
    stack_capture_lite_skel
    stack_capture_lite_obj
    stack_capture_lite
    "${CMAKE_CURRENT_SOURCE_DIR}/stack_capture_lite.bpf.c"
    "${CMAKE_CURRENT_SOURCE_DIR}"
)
add_custom_target(cpa_bpf_skel_stack_capture_lite DEPENDS "${stack_capture_lite_skel}")
add_dependencies(cpa_bpf_skeletons cpa_bpf_skel_stack_capture_lite)

# Pagefault variant for --pagefault (5.4+): the new anonymous page judge and
# the address-space hooks, on top of the regular capture program.
add_bpf_skeleton(
    stack_capture_pagefault_skel
    stack_capture_pagefault_obj
    stack_capture_pagefault
    "${CMAKE_CURRENT_SOURCE_DIR}/stack_capture_pagefault.bpf.c"
    "${CMAKE_CURRENT_SOURCE_DIR}"
)
add_custom_target(cpa_bpf_skel_stack_capture_pagefault DEPENDS "${stack_capture_pagefault_skel}")
add_dependencies(cpa_bpf_skeletons cpa_bpf_skel_stack_capture_pagefault)

# The host loader includes every generated skeleton.
set_property(SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/stack_capture.c"
             APPEND PROPERTY OBJECT_DEPENDS "${stack_capture_ringbuf_skel}" "${stack_capture_lite_skel}"
             "${stack_capture_pagefault_skel}")
