// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include <stdbool.h>
#include <string.h>
#include <stdatomic.h>
#include <offcpu_capture.h>
#include <bpf_event_poll.h>
#include "cpa_capture_mode.h"
#include "cpa_capture_stats.h"
#include "cpa_runtime.h"
#include "cli_common.h"
#include "cpa_unwinder.h"
#include "cpa_drop_policy.h"
#include "cli_counter_helper.h"

/**
 * @file cpa_bpf_capture.c
 * @brief BPF capture worker for building and queueing stack samples.
 */

/**
 * BPF capture state machine used by pause/resume and worker lifecycle.
 */
enum cpa_capture_state { STACK_PROCESS_STATE_INIT = 0, STACK_PROCESS_STATE_PAUSE, STACK_PROCESS_STATE_RUNNING, STACK_PROCESS_STATE_EXIT };
struct bpf_capture_config {
	unsigned int stack_size;
	unsigned int freq;
	unsigned int pid;
};

struct cli_counter *bpf_exec_counter = NULL;

static struct bpf_capture_config bpf_capture_config = { 0 };

static char kernel_comm[TASK_COMM_LEN] = "[kernel]";

static atomic_int capture_state;

static bool offcpu = false;
static bool process_exit_enabled = false;
static bool stack_capture_enabled = false;
static bool offcpu_capture_enabled = false;
static bool kernel_only_fastpath = false;
static pthread_mutex_t kernel_only_fastpath_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t kernel_only_fastpath_idle = PTHREAD_COND_INITIALIZER;
static unsigned int kernel_only_fastpath_active;
static bool kernel_only_fastpath_blocked;
static pthread_mutex_t capture_callbacks_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t capture_callbacks_idle = PTHREAD_COND_INITIALIZER;
static unsigned int capture_callbacks_inflight;
static bool capture_callbacks_blocked;

/*
 * The two callback gates prevent use-after-detach during pause/shutdown. The
 * blocked flag rejects new callbacks, while the active/inflight counter lets
 * teardown wait until callbacks already inside userspace have returned.
 */
static unsigned long cpa_stack_count_from_event(unsigned int type, unsigned long diff_ns)
{
	unsigned long count = offcpu ? diff_ns : 1;

	if (type & STACK_EVENT_IRQOFF)
		count = (diff_ns / (1000 * 1000 * 1000 / bpf_capture_config.freq)) + 1;

	return count;
}

static void kernel_only_fastpath_reset(void)
{
	pthread_mutex_lock(&kernel_only_fastpath_lock);
	kernel_only_fastpath_active = 0;
	kernel_only_fastpath_blocked = false;
	pthread_mutex_unlock(&kernel_only_fastpath_lock);
}

static bool kernel_only_fastpath_enter(void)
{
	bool entered = false;

	if (!kernel_only_fastpath)
		return false;

	pthread_mutex_lock(&kernel_only_fastpath_lock);
	if (atomic_load_explicit(&capture_state, memory_order_acquire) == STACK_PROCESS_STATE_RUNNING && !kernel_only_fastpath_blocked) {
		kernel_only_fastpath_active++;
		entered = true;
	}
	pthread_mutex_unlock(&kernel_only_fastpath_lock);

	return entered;
}

static void kernel_only_fastpath_leave(void)
{
	pthread_mutex_lock(&kernel_only_fastpath_lock);
	if (kernel_only_fastpath_active > 0)
		kernel_only_fastpath_active--;
	if (kernel_only_fastpath_blocked && kernel_only_fastpath_active == 0)
		pthread_cond_broadcast(&kernel_only_fastpath_idle);
	pthread_mutex_unlock(&kernel_only_fastpath_lock);
}

static void kernel_only_fastpath_pause(void)
{
	if (!kernel_only_fastpath)
		return;

	pthread_mutex_lock(&kernel_only_fastpath_lock);
	kernel_only_fastpath_blocked = true;
	pthread_mutex_unlock(&kernel_only_fastpath_lock);
}

static void kernel_only_fastpath_wait_idle(void)
{
	if (!kernel_only_fastpath)
		return;

	pthread_mutex_lock(&kernel_only_fastpath_lock);
	while (kernel_only_fastpath_active > 0)
		pthread_cond_wait(&kernel_only_fastpath_idle, &kernel_only_fastpath_lock);
	pthread_mutex_unlock(&kernel_only_fastpath_lock);
}

static void kernel_only_fastpath_resume(void)
{
	if (!kernel_only_fastpath)
		return;

	pthread_mutex_lock(&kernel_only_fastpath_lock);
	kernel_only_fastpath_blocked = false;
	pthread_mutex_unlock(&kernel_only_fastpath_lock);
}

static void capture_callbacks_reset(void)
{
	pthread_mutex_lock(&capture_callbacks_lock);
	capture_callbacks_inflight = 0;
	capture_callbacks_blocked = false;
	pthread_mutex_unlock(&capture_callbacks_lock);
}

static bool capture_callback_enter(void)
{
	bool entered = false;

	pthread_mutex_lock(&capture_callbacks_lock);
	if (atomic_load_explicit(&capture_state, memory_order_acquire) == STACK_PROCESS_STATE_RUNNING && !capture_callbacks_blocked) {
		capture_callbacks_inflight++;
		entered = true;
	}
	pthread_mutex_unlock(&capture_callbacks_lock);

	return entered;
}

static void capture_callback_leave(void)
{
	pthread_mutex_lock(&capture_callbacks_lock);
	if (capture_callbacks_inflight > 0)
		capture_callbacks_inflight--;
	if (capture_callbacks_blocked && capture_callbacks_inflight == 0)
		pthread_cond_broadcast(&capture_callbacks_idle);
	pthread_mutex_unlock(&capture_callbacks_lock);
}

static void capture_callbacks_pause(void)
{
	pthread_mutex_lock(&capture_callbacks_lock);
	capture_callbacks_blocked = true;
	pthread_mutex_unlock(&capture_callbacks_lock);
}

static void capture_callbacks_wait_idle(void)
{
	pthread_mutex_lock(&capture_callbacks_lock);
	while (capture_callbacks_inflight > 0)
		pthread_cond_wait(&capture_callbacks_idle, &capture_callbacks_lock);
	pthread_mutex_unlock(&capture_callbacks_lock);
}

static void capture_callbacks_resume(void)
{
	pthread_mutex_lock(&capture_callbacks_lock);
	capture_callbacks_blocked = false;
	pthread_mutex_unlock(&capture_callbacks_lock);
}

/**
 * Copy kernel stack frames from event payload into normalized stack sample.
 */
static void fill_sample_kstack(struct stack_sample *sample, const struct stack_event *event)
{
	size_t kstack_level = event->kstack_sz;

	if (kstack_level > MAX_FP_STACK_LEVEL)
		kstack_level = MAX_FP_STACK_LEVEL;

	sample->kstack_fp_level = kstack_level;
	if (kstack_level > 0)
		memcpy(sample->kstack_fp, event->kstack, kstack_level * sizeof(unsigned long));
}

/**
 * Build metadata-only sample for kthread/drop-pressure events.
 */
static struct stack_sample *stack_sample_kernel_build(struct stack_event *event, bool drop)
{
	struct stack_sample *sample = calloc(1, sizeof(struct stack_sample));
	if (!sample)
		return NULL;

	sample->type = event->type;
	sample->user_mode = event->user_mode;
	fill_sample_kstack(sample, event);

	sample->stack_count = cpa_stack_count_from_event(event->type, event->diff_ns);
	if (drop)
		sample->type |= STACK_EVENT_DROP_BY_PRESSURE;

	sample->cpu = event->cpu;
	sample->cgid = event->cgid;
	sample->pid = event->pid;
	sample->timestamp = event->timestamp;

	memcpy(sample->comm, event->comm, TASK_COMM_LEN);
	if (event->type & STACK_EVENT_KTHREAD)
		memcpy(sample->group_comm, kernel_comm, TASK_COMM_LEN);
	else
		memcpy(sample->group_comm, event->group_comm, TASK_COMM_LEN);

	return sample;
}

/**
 * Build full user-mode unwind sample with captured stack/register context.
 */
static struct stack_sample *stack_sample_build(struct stack_event *e, const char *stack_content)
{
	struct stack_sample *sample = (struct stack_sample *)malloc(sizeof(struct gu_stack_info) + e->stack_size + PT_REGS_SIZE + sizeof(struct stack_sample));
	if (!sample) {
		CLI_ERROR("malloc stack failed!");
		return sample;
	}

	sample->type = e->type;
	sample->timestamp = e->timestamp;
	sample->user_mode = e->user_mode;
	fill_sample_kstack(sample, e);

	sample->stack_count = cpa_stack_count_from_event(e->type, e->diff_ns);

	sample->cgid = e->cgid;
	sample->pid = e->pid;

	memcpy(sample->comm, e->comm, TASK_COMM_LEN);
	memcpy(sample->group_comm, e->group_comm, TASK_COMM_LEN);
	sample->cpu = e->cpu;

	struct gu_stack_info *stack = (struct gu_stack_info *)(sample + 1);
	sample->info = stack;
	memset(stack, 0, sizeof(struct gu_stack_info));

	stack->stack_size = e->stack_size;
	/*
	 * See struct stack_event::pid. offcpu samples carry TID here so
	 * libgunwinder resolves the blocked thread's stack snapshot correctly.
	 */
	stack->pid = e->pid;
	stack->unique_id = e->unique_id;
	stack->regs_size = PT_REGS_SIZE;
	stack->stack_data = (uint8_t *)(stack + 1);
	stack->regs = (struct pt_regs *)&(stack->stack_data[stack->stack_size]);

	unsigned int ustack_fp_size = e->ustack_fp_size;
	if (ustack_fp_size > sizeof(e->ustack_fp))
		ustack_fp_size = sizeof(e->ustack_fp);
	memcpy(stack->ustack_fp, e->ustack_fp, ustack_fp_size);
	stack->ustack_fp_level = ustack_fp_size / sizeof(uint64_t);

	memcpy(stack->regs, e->regs, PT_REGS_SIZE);
	memcpy(stack->stack_data, stack_content, stack->stack_size);

	return sample;
}

pthread_mutex_t bpf_exec_counter_mutex = PTHREAD_MUTEX_INITIALIZER;

static void cpa_bpf_exec_counter_destroy(void)
{
	pthread_mutex_lock(&bpf_exec_counter_mutex);
	if (bpf_exec_counter) {
		cli_counter_destroy(bpf_exec_counter);
		bpf_exec_counter = NULL;
	}
	pthread_mutex_unlock(&bpf_exec_counter_mutex);
}

static char *probe = NULL;

static void cpa_bpf_capture_disable_modules(void)
{
	if (process_exit_enabled) {
		DISABLE_MODULE_BPF(process_exit);
		process_exit_enabled = false;
	}
	if (stack_capture_enabled) {
		DISABLE_MODULE_BPF(stack_capture);
		stack_capture_enabled = false;
	}
	if (offcpu_capture_enabled) {
		DISABLE_MODULE_BPF(offcpu_capture);
		offcpu_capture_enabled = false;
	}
	if (probe) {
		free(probe);
		probe = NULL;
	}
	offcpu = false;
}

void cpa_print_bpf_exec_time_dist(void)
{
	if (!bpf_exec_counter)
		return;
	pthread_mutex_lock(&bpf_exec_counter_mutex);
	cli_counter_print(bpf_exec_counter);
	pthread_mutex_unlock(&bpf_exec_counter_mutex);
}

/**
 * Build kernel/user stack sample and push into unwind queue.
 */
static void stack_capture_event_process(void *event, unsigned int size, void *user_ctx)
{
	bool kernel_only_entered = false;
	struct stack_event *e = (struct stack_event *)event;
	unsigned int stack_payload_size = 0;
	const char *stack = NULL;
	int ret = 0;
	struct stack_sample *sample = NULL;

	if (!capture_callback_enter())
		return;

	(void)user_ctx;
	stack = (const char *)(e + 1); /* stack_content follows event struct. */

	if (size < sizeof(*e))
		goto out;

	stack_payload_size = size - sizeof(*e);
	if (e->stack_size > stack_payload_size)
		goto out;

	pthread_mutex_lock(&bpf_exec_counter_mutex);
	if (bpf_exec_counter)
		cli_counter_add(bpf_exec_counter, e->bpf_exec_time);
	pthread_mutex_unlock(&bpf_exec_counter_mutex);

	if (kernel_only_fastpath) {
		if (!kernel_only_fastpath_enter())
			goto out;
		kernel_only_entered = true;
		cpa_emit_kernel_only_sample(e, bpf_capture_config.freq);
		goto out;
	}

	enum drop_sample_result drop_state = should_drop_sample();

	if (e->type & STACK_EVENT_KTHREAD || drop_state != DROP_SAMPLE_RESULT_PASS)
		sample = stack_sample_kernel_build(e, drop_state != DROP_SAMPLE_RESULT_PASS);
	else
		sample = stack_sample_build(e, stack);

	if (!sample)
		goto out;

	ret = cpa_add_stack_event(sample);

	if (ret)
		free(sample);

out:
	if (kernel_only_entered)
		kernel_only_fastpath_leave();
	capture_callback_leave();
}

/**
 * Enqueue process exit event for unwinder queue.
 */
static void exit_event_process(void *event, unsigned int sz, void *user_ctx)
{
	struct exit_event *e = NULL;

	(void)sz;
	(void)user_ctx;
	if (!capture_callback_enter())
		return;

	e = malloc(sizeof(struct exit_event));
	if (!e)
		goto out;

	e->exit_ts = ((struct process_exit_event *)event)->ts;
	e->pid = ((struct process_exit_event *)event)->pid;

	int ret = cpa_add_pid_exit_event(e);
	if (ret)
		free(e);

out:
	capture_callback_leave();
}

/**
 * Configure off-CPU capture backend and attach finish_task_switch listener.
 */
static int cpa_bpf_offcpu_capture_init(void *ctx)
{
	if (set_offcpu_capture_size(bpf_capture_config.stack_size) < 0) {
		CLI_ERROR("Failed to set offcpu capture size %u", bpf_capture_config.stack_size);
		return CPA_INIT_FAILED;
	}

	if (INIT_MODULE_BPF(offcpu_capture))
		return CPA_INIT_FAILED;

	struct offcpu_capture_ctx offcpu_capture_init_ctx;

	const char *comm = get_arg_by_name(ctx, "comm");
	if (cli_arg_is_null_default(comm))
		comm = NULL;

	if (comm)
		snprintf(offcpu_capture_init_ctx.comm, sizeof(offcpu_capture_init_ctx.comm), "%s", comm);
	else
		memset(offcpu_capture_init_ctx.comm, 0, TASK_COMM_LEN);

	offcpu_capture_init_ctx.pid = bpf_capture_config.pid;

	if (setup_offcpu_capture_event(bpf_capture_config.freq, stack_capture_event_process, &offcpu_capture_init_ctx) < 0) {
		CLI_ERROR("Failed to setup stack capture event");
		DISABLE_MODULE_BPF(offcpu_capture);
		return CPA_INIT_FAILED;
	}

	offcpu_capture_enabled = true;
	offcpu = true;
	atomic_store_explicit(&capture_state, STACK_PROCESS_STATE_RUNNING, memory_order_release);

	return CPA_INIT_SUCCESS;
}

/**
 * Configure on-CPU capture backend (kernel or userspace stack sampling).
 */
static int cpa_bpf_oncpu_capture_init(void *ctx)
{
	if (set_stack_capture_size(bpf_capture_config.stack_size) < 0) {
		CLI_ERROR("Failed to set stack capture size %u", bpf_capture_config.stack_size);
		return CPA_INIT_FAILED;
	}

	if (INIT_MODULE_BPF(stack_capture))
		return CPA_INIT_FAILED;

	struct stack_capture_ctx stack_capture_init_ctx;
	memset(&stack_capture_init_ctx, 0, sizeof(stack_capture_init_ctx));

	const char *probe_name = get_arg_by_name(ctx, "probe");
	const char *comm = get_arg_by_name(ctx, "comm");
	if (cli_arg_is_null_default(probe_name)) {
		stack_capture_init_ctx.probe_name = NULL;
	} else {
		probe = strdup(probe_name);
		if (!probe) {
			DISABLE_MODULE_BPF(stack_capture);
			return CPA_INIT_FAILED;
		}
		stack_capture_init_ctx.probe_name = probe;
	}

	memset(stack_capture_init_ctx.comm, 0, TASK_COMM_LEN);
	if (!cli_arg_is_null_default(comm))
		snprintf(stack_capture_init_ctx.comm, sizeof(stack_capture_init_ctx.comm), "%s", comm);

	stack_capture_init_ctx.only_kernel = kernel_only_fastpath;
	stack_capture_init_ctx.pid = bpf_capture_config.pid;

	if (setup_stack_capture_event(bpf_capture_config.freq, stack_capture_event_process, &stack_capture_init_ctx) < 0) {
		CLI_ERROR("Failed to setup stack capture event");
		DISABLE_MODULE_BPF(stack_capture);
		free(probe);
		probe = NULL;
		return CPA_INIT_FAILED;
	}

	stack_capture_enabled = true;
	atomic_store_explicit(&capture_state, STACK_PROCESS_STATE_RUNNING, memory_order_release);

	return CPA_INIT_SUCCESS;
}

static enum cpa_worker_init_result cpa_bpf_capture_init_fn(void *ctx, void *worker_ctx)
{
	const char *backend = get_arg_by_name(ctx, "backend");
	if (strncmp(backend, "bpf", strlen("bpf")) != 0)
		return CPA_INIT_SKIP;

	atomic_init(&capture_state, STACK_PROCESS_STATE_INIT);
	kernel_only_fastpath = cpa_kernel_only_fastpath_requested(ctx);
	kernel_only_fastpath_reset();
	capture_callbacks_reset();

	bpf_capture_config.stack_size = atoi(get_arg_by_name(ctx, "stack_size"));
	if (bpf_capture_config.stack_size < 4096 || bpf_capture_config.stack_size > 65536 || bpf_capture_config.stack_size % 4096 != 0) {
		CLI_ERROR("Please use stack_size >= 4096 && <= 65536 && align to 4096");
		return CPA_INIT_FAILED;
	}
	/*
	 * Clamp to the verifier-safe payload size. The BPF scratch buffer must leave
	 * one full page of headroom because user stacks are copied page by page.
	 */
	if (bpf_capture_config.stack_size > MAX_STACK_EVENT_USER_STACK_SIZE)
		bpf_capture_config.stack_size = MAX_STACK_EVENT_USER_STACK_SIZE;

	bpf_capture_config.freq = atoi(get_arg_by_name(ctx, "freq"));
	if (bpf_capture_config.freq > 99 || bpf_capture_config.freq < 9) {
		CLI_ERROR("Please use frequency in range [9, 99]");
		return CPA_INIT_FAILED;
	}

	bpf_capture_config.pid = atoi(get_arg_by_name(ctx, "pid"));
	if (bpf_capture_config.pid < 0) {
		CLI_ERROR("Please use pid >= 0");
		return CPA_INIT_FAILED;
	}

	bpf_exec_counter = cli_counter_init("bpf_exec_time", CLI_COUNTER_TYPE_TIME_NS);
	if (!bpf_exec_counter)
		CLI_ERROR("Failed to init bpf_exec_counter");

	if (!kernel_only_fastpath) {
		if (INIT_MODULE_BPF(process_exit)) {
			cpa_bpf_exec_counter_destroy();
			return CPA_INIT_FAILED;
		}

		if (setup_process_exit_event(exit_event_process) < 0) {
			DISABLE_MODULE_BPF(process_exit);
			cpa_bpf_exec_counter_destroy();
			return CPA_INIT_FAILED;
		}
		process_exit_enabled = true;
	}

	int offcpu = atoi(get_arg_by_name(ctx, "offcpu"));
	if (offcpu) {
		if (cpa_bpf_offcpu_capture_init(ctx) < 0) {
			cpa_bpf_capture_disable_modules();
			cpa_bpf_exec_counter_destroy();
			return CPA_INIT_FAILED;
		}
	} else {
		if (cpa_bpf_oncpu_capture_init(ctx) < 0) {
			cpa_bpf_capture_disable_modules();
			cpa_bpf_exec_counter_destroy();
			return CPA_INIT_FAILED;
		}
	}

	atomic_store_explicit(&capture_state, STACK_PROCESS_STATE_RUNNING, memory_order_release);

	return CPA_INIT_SUCCESS;
}

/**
 * Tear down counter and detach capture worker.
 *
 * Permanent shutdown moves the state to EXIT and drains both callback gates
 * before modules are disabled. Pause uses the same drain path but keeps module
 * state ready for restore.
 */
static void cpa_bpf_capture_destroy_fn(void *worker_ctx)
{
	atomic_store_explicit(&capture_state, STACK_PROCESS_STATE_EXIT, memory_order_release);
	kernel_only_fastpath_pause();
	capture_callbacks_pause();
	capture_callbacks_wait_idle();
	kernel_only_fastpath_wait_idle();
	kernel_only_fastpath = false;
	cpa_bpf_capture_disable_modules();
	cpa_bpf_exec_counter_destroy();
}

static void cpa_bpf_capture_pause_fn(void *worker_ctx)
{
	atomic_store_explicit(&capture_state, STACK_PROCESS_STATE_PAUSE, memory_order_release);
	kernel_only_fastpath_pause();
	capture_callbacks_pause();
	capture_callbacks_wait_idle();
	kernel_only_fastpath_wait_idle();
}

/**
 * Restore worker state and clear execution time accounting.
 */
static void cpa_bpf_capture_restore_fn(void *worker_ctx)
{
	pthread_mutex_lock(&bpf_exec_counter_mutex);
	if (bpf_exec_counter)
		cli_counter_clear(bpf_exec_counter);
	pthread_mutex_unlock(&bpf_exec_counter_mutex);

	atomic_store_explicit(&capture_state, STACK_PROCESS_STATE_RUNNING, memory_order_release);
	kernel_only_fastpath_resume();
	capture_callbacks_resume();
}

/**
 * Registered runtime worker for BPF capture pipeline.
 */
struct cpa_worker bpf_capture_worker = {
	.worker_name = "bpf_capture_worker",
	.worker_ctx = NULL,
	.worker_index = 10,

	.init_fn = cpa_bpf_capture_init_fn,
	.destroy_fn = cpa_bpf_capture_destroy_fn,
	.pause_fn = cpa_bpf_capture_pause_fn,
	.restore_fn = cpa_bpf_capture_restore_fn,
	.timer_fn = NULL,
	.main_worker_fn = NULL,
};

void cpa_bpf_capture_get_stats(struct cpa_capture_stats *stat)
{
	struct bpf_event_poll_stats poll_stats = { 0 };

	if (!stat)
		return;

	memset(stat, 0, sizeof(*stat));
	bpf_event_poll_get_stats(&poll_stats);
	stat->lost_events = poll_stats.lost_events;
}
