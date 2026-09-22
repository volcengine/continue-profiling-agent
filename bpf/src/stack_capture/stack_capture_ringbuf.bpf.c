// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance
//
// Ring buffer datapath variant of stack_capture. Compiled into a distinct
// BPF object/skeleton (stack_capture_ringbuf_bpf); userspace selects it
// when BPF_MAP_TYPE_RINGBUF is available.

#define CPA_USE_RINGBUF
#include "stack_capture.bpf.c"
