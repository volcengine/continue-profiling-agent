// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CPA_UNWINDER_H
#define CPA_UNWINDER_H

#include "cli.h"
#include "cli_common.h"
#include "cli_single_queue.h"
#include "gunwinder/unwinder.h"
#include <cpa_bpf/bpf_event.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * @file cpa_unwinder.h
 * @brief Unwinder pipeline interfaces and public stack sample contracts.
 */

/**
 * Event bit flags carried in struct stack_sample::type.
 */
#define STACK_EVENT_OFFCPU (1 << STACK_EVENT_MAX_BIT)
#define STACK_EVENT_DROP_BY_PRESSURE (1 << (STACK_EVENT_MAX_BIT + 1))
#define ALREADY_RESTORE_FLAG (~0UL)

/**
 * struct stack_sample - normalized stack sample consumed by the unwinder
 * @type: sample type bits from BPF/perf capture and CPA-local flags
 * @state: optional state marker used by off-CPU reporting paths
 * @cpu: cpu on which the sample was captured
 * @pid: pid owning the captured sample
 * @timestamp: sample timestamp in nanoseconds
 * @cgid: cgroup id associated with the sample
 * @stack_count: aggregated sample count or weight contributed by this record
 * @user_mode: true when the interrupted context was user mode
 * @kstack_fp: normalized kernel instruction pointers captured with the sample
 * @kstack_fp_level: number of valid entries in @kstack_fp
 * @comm: thread comm recorded for the sample
 * @group_comm: process/group comm recorded for the sample
 * @info: libgunwinder user-stack/register snapshot, or NULL for kernel-only paths
 */
struct stack_sample {
	int type;

	int state;
	int cpu, pid;
	unsigned long timestamp, cgid, stack_count;
	bool user_mode;

	unsigned long kstack_fp[MAX_FP_STACK_LEVEL + 1];
	unsigned long kstack_fp_level;

	char comm[TASK_COMM_LEN];
	char group_comm[TASK_COMM_LEN];
	struct gu_stack_info *info;
};

/**
 * cpa_add_stack_event - push one captured stack sample into the unwind queue
 * @sample: populated sample object
 *
 * Return: 0 on success, negative value on failure.
 */
int cpa_add_stack_event(struct stack_sample *sample);

/**
 * struct exit_event - process-exit record consumed by the unwinder loop
 * @exit_ts: process exit timestamp
 * @pid: pid that exited
 */
struct exit_event {
	uint64_t exit_ts;
	uint32_t pid;
};

/**
 * cpa_add_pid_exit_event - push one process-exit event into the unwind queue
 * @exit: exit-event payload
 *
 * Return: 0 on success, negative value on failure.
 */
int cpa_add_pid_exit_event(struct exit_event *exit);

/**
 * cpa_add_ksyms_reload_event - request a kernel symbol refresh
 */
void cpa_add_ksyms_reload_event(void);

/**
 * struct unwinder_stat - aggregated unwind worker statistics
 * @sample_backtrace_times: total unwind attempts
 * @sample_backtrace_times_fp: unwind attempts attributed to frame-pointer mode
 * @sample_backtrace_times_fp_better: retries where FP beat the first unwind mode
 * @sample_backtrace_times_dwarf: unwind attempts attributed to DWARF mode
 * @stack_queue_len: last observed unwind queue length
 */
struct unwinder_stat {
	unsigned long sample_backtrace_times;
	unsigned long sample_backtrace_times_fp;
	unsigned long sample_backtrace_times_fp_better;
	unsigned long sample_backtrace_times_dwarf;
	unsigned long stack_queue_len;
};

/**
 * cpa_get_unwinder_stat - copy the latest unwind statistics snapshot
 * @stat: destination for the current unwind statistics
 */
void cpa_get_unwinder_stat(struct unwinder_stat *stat);

#define CPA_UNWIND_BENCH_BUCKETS 9

/**
 * struct cpa_unwind_bench_stat - DWARF unwind benchmark statistics
 * @enabled: true when monitor benchmark mode is enabled
 * @count: number of measured DWARF unwind operations
 * @total_ns: cumulative measured DWARF unwind latency in nanoseconds
 * @min_ns: minimum measured DWARF unwind latency in nanoseconds
 * @max_ns: maximum measured DWARF unwind latency in nanoseconds
 * @hist: fixed latency histogram buckets in nanoseconds-derived ranges
 */
struct cpa_unwind_bench_stat {
	bool enabled;
	uint64_t count;
	uint64_t total_ns;
	uint64_t min_ns;
	uint64_t max_ns;
	uint64_t hist[CPA_UNWIND_BENCH_BUCKETS];
};

/**
 * cpa_take_unwind_bench_stat - take and reset DWARF unwind benchmark stats
 * @stat: destination for the current benchmark interval statistics
 */
void cpa_take_unwind_bench_stat(struct cpa_unwind_bench_stat *stat);

/**
 * cpa_get_gunwinder_stat - return libgunwinder statistics
 *
 * Return: pointer to the current libgunwinder statistics structure.
 */
struct gu_statistics *cpa_get_gunwinder_stat(void);

/**
 * cpa_emit_kernel_only_sample - emit one BPF kernel-only sample directly into
 * the shared stackmap without using the unwind queue.
 * @event: BPF stack event payload
 * @sample_freq: configured sampling frequency
 */
void cpa_emit_kernel_only_sample(const struct stack_event *event, unsigned int sample_freq);

/**
 * cpa_unwinder_drain_pending - synchronously process all queued unwind samples
 *
 * This helper is used during shutdown/export paths after capture workers stop
 * producing new events but before the shared tracemap is persisted.
 */
void cpa_unwinder_drain_pending(void);

#endif /* CPA_UNWINDER_H */
