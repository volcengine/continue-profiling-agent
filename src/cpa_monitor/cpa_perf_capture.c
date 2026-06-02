// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "gunwinder/unwinder.h"
#include "cpa_runtime.h"
#include "cpa_capture_stats.h"
#include "cli_common.h"
#include "cpa_env.h"
#include <offcpu_capture.h>
#include <cpa_bpf/perf_stack_capture.h>
#include "cli_single_queue.h"
#include "cpa_drop_policy.h"
#include "cpa_unwinder.h"
#include <stdatomic.h>
#include "uthash.h"
#include <asm/ptrace.h>
#include "cpa_nobpf_unwinder_event.h"

#if defined(__CPA_BPF_ARCH_arm64)
#define pt_regs user_pt_regs
#endif

struct perf_capture_config {
	unsigned int freq;
};

enum cpa_capture_state { STACK_PROCESS_STATE_INIT = 0, STACK_PROCESS_STATE_PAUSE, STACK_PROCESS_STATE_RUNNING, STACK_PROCESS_STATE_EXIT };
static atomic_int capture_state;

static struct perf_capture_config perf_capture_config = { 0 };

struct perf_stack_capture_ctx *perf_ctx = NULL;

static struct stack_sample *perf_stack_sample_build(struct perf_stack_event *event, bool drop_dwarf)
{
	struct stack_sample *sample = (struct stack_sample *)malloc(sizeof(struct gu_stack_info) + event->ustack_raw_sz + sizeof(struct pt_regs) + sizeof(struct stack_sample));
	if (!sample) {
		CLI_ERROR("malloc stack failed!");
		return sample;
	}

	sample->timestamp = event->time;
	sample->cgid = event->cgid;
	sample->cpu = event->cpu;
	sample->type = 0;
	sample->user_mode = true;
	sample->pid = event->pid;
	sample->stack_count = 1;

	memset(sample->group_comm, 0, sizeof(sample->group_comm));
	memset(sample->comm, 0, sizeof(sample->comm));

	get_pid_comm_auto_retire(event->pid, sample->group_comm);
	get_pid_comm_direct(event->tid, sample->comm);

	if (event->pid == 0 || sample->comm[0] == '[')
		sample->type |= STACK_EVENT_KTHREAD;
	if (sample->type & STACK_EVENT_KTHREAD)
		sample->user_mode = false;

	sample->kstack_fp_level = event->kstack_sz;
	memcpy(sample->kstack_fp, event->kstack, event->kstack_sz * sizeof(uint64_t));

	struct gu_stack_info *stack = (struct gu_stack_info *)(sample + 1);
	sample->info = stack;

	stack->pid = sample->pid;
	stack->unique_id = 0;
	stack->flags = 0;
	stack->stack_data = (uint8_t *)(stack + 1);

	if (drop_dwarf) {
		sample->info->ustack_fp_level = 0;
		sample->info->stack_size = 0;
		if (!(sample->type & STACK_EVENT_KTHREAD))
			sample->type |= STACK_EVENT_DROP_BY_PRESSURE;
		return sample;
	}

	sample->info->ustack_fp_level = event->ustack_sz;
	memcpy(sample->info->ustack_fp, event->ustack, event->ustack_sz * sizeof(uint64_t));

	sample->info->stack_size = event->ustack_raw_sz;
	memcpy(sample->info->stack_data, event->ustack_raw, event->ustack_raw_sz);

	struct pt_regs *regs = (struct pt_regs *)&(sample->info->stack_data[sample->info->stack_size]);
	memset(regs, 0, sizeof(struct pt_regs));

#if defined(__CPA_BPF_ARCH_arm64)
	regs->regs[29] = event->rbp;
	regs->regs[30] = event->lr;
	regs->pc = event->rip;
	regs->sp = event->rsp;
#else
	regs->rsp = event->rsp;
	regs->rip = event->rip;
	regs->rbp = event->rbp;
#endif

	sample->info->regs = regs;
	sample->info->regs_size = sizeof(struct pt_regs);

	return sample;
}

void perf_capture_handler(struct perf_stack_event *event, void *data)
{
	if (atomic_load_explicit(&capture_state, memory_order_acquire) != STACK_PROCESS_STATE_RUNNING)
		return;

	enum drop_sample_result drop_state = should_drop_sample();

	struct stack_sample *sample = perf_stack_sample_build(event, drop_state != DROP_SAMPLE_RESULT_PASS);

	if (!sample)
		return;

	int ret = cpa_add_stack_event(sample);

	if (ret)
		free(sample);
}

static enum cpa_worker_init_result cpa_perf_capture_init_fn(void *ctx, void *worker_ctx)
{
	const char *backend = get_arg_by_name(ctx, "backend");
	if (strncmp(backend, "perf", strlen("perf")) != 0)
		return CPA_INIT_SKIP;

	atomic_init(&capture_state, STACK_PROCESS_STATE_INIT);

	int offcpu = atoi(get_arg_by_name(ctx, "offcpu"));
	const char *probe = get_arg_by_name(ctx, "probe");

	if (offcpu || !cli_arg_is_null_default(probe)) {
		CLI_ERROR("offcpu and probe only support on bpf backend");
		return CPA_INIT_FAILED;
	}

	perf_capture_config.freq = atoi(get_arg_by_name(ctx, "freq"));
	if (perf_capture_config.freq > 99 || perf_capture_config.freq < 9) {
		CLI_ERROR("Please use frequency in range [9, 99]");
		return CPA_INIT_FAILED;
	}

	if (perf_ctx) {
		perf_stack_capture_cleanup(perf_ctx);
		perf_ctx = NULL;
	}

	perf_ctx = perf_setup_stack_capture_event(perf_capture_config.freq, perf_capture_handler, NULL);
	if (!perf_ctx) {
		CLI_ERROR("Failed to setup stack capture event");
		return CPA_INIT_FAILED;
	}

	atomic_store_explicit(&capture_state, STACK_PROCESS_STATE_RUNNING, memory_order_release);

	return CPA_INIT_SUCCESS;
}

static void cpa_perf_capture_destroy_fn(void *worker_ctx)
{
	atomic_store_explicit(&capture_state, STACK_PROCESS_STATE_EXIT, memory_order_release);

	if (perf_ctx) {
		perf_stack_capture_cleanup(perf_ctx);
		perf_ctx = NULL;
	}
}

static void cpa_perf_capture_pause_fn(void *worker_ctx)
{
	atomic_store_explicit(&capture_state, STACK_PROCESS_STATE_PAUSE, memory_order_release);
}

static void cpa_perf_capture_restore_fn(void *worker_ctx)
{
	atomic_store_explicit(&capture_state, STACK_PROCESS_STATE_RUNNING, memory_order_release);
}

struct cpa_worker perf_capture_worker = {
	.worker_name = "perf_capture_worker",
	.worker_ctx = NULL,
	.worker_index = 10,

	.init_fn = cpa_perf_capture_init_fn,
	.destroy_fn = cpa_perf_capture_destroy_fn,
	.pause_fn = cpa_perf_capture_pause_fn,
	.restore_fn = cpa_perf_capture_restore_fn,
	.timer_fn = NULL,
	.main_worker_fn = NULL,
};

void cpa_perf_capture_get_stats(struct cpa_capture_stats *stat)
{
	struct perf_stack_capture_stats perf_stat = { 0 };

	if (!stat)
		return;

	memset(stat, 0, sizeof(*stat));
	perf_stack_capture_get_stats(perf_ctx, &perf_stat);
	stat->lost_events = perf_stat.lost_events;
}
