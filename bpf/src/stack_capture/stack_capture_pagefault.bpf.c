// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance
//
// Pagefault variant: resident anonymous memory of one process (cpa monitor
// --pagefault: Linux 5.4 - 5.18 through page_add_new_anon_rmap, 6.3 and
// later through folio_add_new_anon_rmap; the loader keeps one of the two).
// Perf buffer only; the timer, probe, coredump and exit programs are built
// but never loaded.

#define CPA_PAGEFAULT
#include "stack_capture.bpf.c"
