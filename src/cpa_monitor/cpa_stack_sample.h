// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CPA_STACK_SAMPLE_H
#define CPA_STACK_SAMPLE_H

#include "cli_common.h"
#include "gunwinder/unwinder.h"
#include <cpa_bpf/bpf_event.h>
#include <stdbool.h>
#include <stdint.h>

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
 * @pid: task the record shows: the sampled thread for an off-CPU sample,
 *       the process otherwise
 * @tgid: the process, set once by stack_sample_set_process() when the
 *        sample is built; libgunwinder's process context and every
 *        per-process table are keyed by it, never by @pid
 * @timestamp: sample timestamp in nanoseconds
 * @cgid: cgroup id associated with the sample; the process for an off-CPU
 *        sample, which carries no cgroup id
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
	int signal;
	int signal_code;

	int state;
	int cpu, pid, tgid;
	unsigned long timestamp, cgid, stack_count;
	bool user_mode;

	unsigned long kstack_fp[MAX_FP_STACK_LEVEL + 1];
	unsigned long kstack_fp_level;

	char comm[TASK_COMM_LEN];
	char group_comm[TASK_COMM_LEN];
	struct gu_stack_info *info;
};

/**
 * stack_sample_set_process - give a sample its process
 * @sample: the sample being built
 * @tgid: its process
 * @tid: the sampled thread, or 0
 *
 * The one setter of struct stack_sample::tgid; it also keys the
 * libgunwinder snapshot by the process and names the thread to read it
 * through.
 */
static inline void stack_sample_set_process(struct stack_sample *sample,
					    int tgid, int tid)
{
	sample->tgid = tgid;
	if (sample->info) {
		sample->info->pid = tgid;
		sample->info->tid = tid;
	}
}

#endif
