// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance
//
// The ringbuf variant with the user stack copy bounded by the VMA holding SP
// (bpf_find_vma).  Same maps and programs as stack_capture_ringbuf, so it is
// opened into that skeleton with only its ELF swapped; stack_capture.c does so
// only where bpf_find_vma was probed, and falls back to the plain ringbuf
// object when this one does not load.

#define CPA_USE_RINGBUF
#define CPA_STACK_VMA_BOUND
#include "stack_capture.bpf.c"
