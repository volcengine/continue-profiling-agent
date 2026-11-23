// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef __CPA_PAGEFAULT_H__
#define __CPA_PAGEFAULT_H__

#include <stdbool.h>
#include <stdint.h>

#include <cpa_bpf/pagefault_sample.h>

#include "cpa_stack_sample.h"

/*
 * cpa monitor --pagefault: resident anonymous memory of one process (--pid,
 * or from its exec on, the --first_match winner of a rule selection), by
 * allocating stack, as a live set written every second.
 *
 * The profile's value is bytes.  The count of stack S in second T is the
 * estimated resident anonymous memory that S faulted in and that was still
 * mapped at T, so reading the one-second window [T, T+1) gives the live set
 * at T and the timeline's per-second total is the resident memory curve.
 */

/* Parse and validate the options; set up the capture.  Before stack_capture. */
int cpa_pagefault_configure(void *cli_ctx);
bool cpa_pagefault_enabled(void);

/* A sampled page, unwound and interned as @ids_id (by its process' unwind worker). */
void cpa_pagefault_on_alloc(const struct stack_sample *sample, uint32_t ids_id);
/* A sampled page whose stack could not be queued. */
void cpa_pagefault_on_lost(const struct pf_sample_meta *pf, uint64_t ts);

#endif
