// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CPA_CAPTURE_STATS_H
#define CPA_CAPTURE_STATS_H

#include <stdint.h>

/**
 * @file cpa_capture_stats.h
 * @brief Capture backend counters exported to the stat worker.
 */

/**
 * struct cpa_capture_stats - transport-level capture counters
 * @lost_events: number of records dropped by the backend transport
 */
struct cpa_capture_stats {
	uint64_t lost_events;
	/* EXIT NONZERO events received (BPF backend) */
	uint64_t exit_capture_count;
	/* of those, dropped by --exit_target_env_*: not matching, not read */
	uint64_t exit_env_mismatch_drop_count;
	uint64_t exit_env_unknown_drop_count;
};

/**
 * cpa_bpf_capture_get_stats - snapshot BPF backend transport counters
 * @stat: destination statistics object
 */
void cpa_bpf_capture_get_stats(struct cpa_capture_stats *stat);

/**
 * cpa_perf_capture_get_stats - snapshot perf backend transport counters
 * @stat: destination statistics object
 */
void cpa_perf_capture_get_stats(struct cpa_capture_stats *stat);

#endif /* CPA_CAPTURE_STATS_H */
