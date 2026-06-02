// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef __CPA_BPF_CAPTURE_H__
#define __CPA_BPF_CAPTURE_H__

/**
 * @file cpa_bpf_capture.h
 * @brief Public hooks for the CPA BPF capture worker integration.
 */

/**
 * cpa_print_bpf_exec_time_dist - print the BPF execution-time histogram
 *
 * Dump the aggregated per-sample BPF execution time distribution collected by
 * the capture worker.
 */
void cpa_print_bpf_exec_time_dist(void);

#endif /* __CPA_BPF_CAPTURE_H__ */
