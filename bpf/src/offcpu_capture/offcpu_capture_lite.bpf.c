// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance
//
// Lite variant of offcpu_capture for kernels without bpf_get_stack or
// bounded loops (before 5.3, e.g. 4.14): kernel stacks by stack id, a
// 16 KiB user-stack window, no frame-pointer user stack.

#define CPA_LITE
#include "offcpu_capture.bpf.c"
