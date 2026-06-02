// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "cpa_unwinder.h"
#include "cli_stackmap.h"
#include "cli_stackmap_private.h"
#include "cpa_capture_mode.h"
#include "cpa_env.h"
#include "cli_profile_metadata.h"
#include "cpa_drop_policy.h"
#include "cpa_runtime.h"
#include "cpa_debug.h"
#include "cpa_unwind_state.h"
#include "uthash.h"

#include <gunwinder/unwinder.h>
#include <gunwinder/unwinder_types.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/**
 * @file cpa_unwinder.c
 * @brief Implements the unwinder worker for cpa.
 *
 * This worker manages the lifecycle of the unwinder library,
 * including initialization, cleanup, and re-initialization on pause.
 */

static struct gu_context *gu_ctx = NULL;
static pthread_mutex_t unwind_stat_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t stack_queue_lock = PTHREAD_MUTEX_INITIALIZER;

static char default_env_name[] = "SYSTEM";

struct single_queue pid_exit_queue;
struct single_queue stack_queue;

#define MIN_QUEUE_SIZE 16
#define CPA_RECORD_DAY_MS (24ULL * 60ULL * 60ULL * 1000ULL)
#define CPA_NS_PER_MS 1000000ULL
#define CPA_NS_PER_US 1000ULL

/* Unwind stop reason strings exposed through stack symbolization. */

static const char *const stop_reason_str[] = {
	[GU_UNWIND_REASON_OK] = "NO_ERROR",
	[GU_UNWIND_REASON_NO_REGS] = "<# NO REGS #>",
	[GU_UNWIND_REASON_NO_ELF] = "<# NO ELF #>",
	[GU_UNWIND_REASON_NO_CFI] = "<# NO CFI #>",
	[GU_UNWIND_REASON_CFI_FAIL] = "<# CFI FAIL #>",
	[GU_UNWIND_REASON_ARCH_FAIL] = "<# ARCH FAIL #>",
	[GU_UNWIND_REASON_PROCESS_EXIT] = "<# PROCESS EXIT #>",
	[GU_UNWIND_REASON_LANG_SKIP] = "<# DROP BY LANG TYPE #>",
	[GU_UNWIND_REASON_TRUNCATED] = "<# TRUNCATED #>",
	[GU_UNWIND_REASON_NO_EXEC_PC] = "<# NO EXEC PC #>",
	[GU_UNWIND_REASON_CFI_FRAME_DECODE_FAILED] = "<# CFI FRAME DECODE_FAILED #>",
	[GU_UNWIND_REASON_CFI_FRAME_CFA_FAILED] = "<# CFI FRAME CFA FAILED #>",
	[GU_UNWIND_REASON_CFI_FRAME_CFA_CALC_FAILED] = "<# CFI FRAME CFA CALC FAILED #>",
	[GU_UNWIND_REASON_UNKNOWN] = "<# OTHER #>",
};

static struct gu_init_cfg gu_init_cfg = { 0 };
static bool include_full_path = false;
static bool disable_sym = false;
static int queue_size = 0;
static bool unwinder_configured = false;

struct cpa_worker unwinder_worker;
static atomic_bool accept_events;

#define CPA_KERNEL_SYMBOL_CACHE_MAX 2048

struct cpa_kernel_symbol_cache_entry {
	unsigned long addr;
	char symbol[256];
	UT_hash_handle hh;
};

static struct cpa_kernel_symbol_cache_entry *kernel_symbol_cache = NULL;
static pthread_mutex_t kernel_symbol_cache_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t record_time_base_lock = PTHREAD_MUTEX_INITIALIZER;
static bool record_time_base_valid = false;
static uint64_t record_time_base_sample_ns;
static uint64_t record_time_base_ms;
static void cpa_unwind(struct stack_sample *sample);

static pthread_mutex_t unwind_bench_lock = PTHREAD_MUTEX_INITIALIZER;
static atomic_bool unwind_bench_enabled = ATOMIC_VAR_INIT(false);
static struct cpa_unwind_bench_stat unwind_bench_stat = { 0 };

static uint64_t cpa_monotonic_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;

	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int cpa_unwind_bench_bucket(uint64_t duration_ns)
{
	static const uint64_t upper_bounds_ns[CPA_UNWIND_BENCH_BUCKETS] = {
		1ULL * CPA_NS_PER_US, 4ULL * CPA_NS_PER_US, 16ULL * CPA_NS_PER_US, 64ULL * CPA_NS_PER_US, 256ULL * CPA_NS_PER_US, 512ULL * CPA_NS_PER_US, 1024ULL * CPA_NS_PER_US, 2048ULL * CPA_NS_PER_US, 4096ULL * CPA_NS_PER_US,
	};

	for (unsigned int i = 0; i < CPA_UNWIND_BENCH_BUCKETS; i++) {
		if (duration_ns < upper_bounds_ns[i])
			return (int)i;
	}

	return -1;
}

static void cpa_unwind_bench_clear_locked(bool enabled)
{
	memset(&unwind_bench_stat, 0, sizeof(unwind_bench_stat));
	unwind_bench_stat.enabled = enabled;
	unwind_bench_stat.min_ns = UINT64_MAX;
}

static void cpa_unwind_bench_reset(bool enabled)
{
	pthread_mutex_lock(&unwind_bench_lock);
	cpa_unwind_bench_clear_locked(enabled);
	pthread_mutex_unlock(&unwind_bench_lock);

	atomic_store_explicit(&unwind_bench_enabled, enabled, memory_order_release);
}

static uint64_t cpa_unwind_bench_start(void)
{
	if (!atomic_load_explicit(&unwind_bench_enabled, memory_order_acquire))
		return 0;

	return cpa_monotonic_ns();
}

static void cpa_unwind_bench_record(uint64_t start_ns)
{
	uint64_t end_ns;
	uint64_t duration_ns;
	int bucket;

	if (!start_ns || !atomic_load_explicit(&unwind_bench_enabled, memory_order_acquire))
		return;

	end_ns = cpa_monotonic_ns();
	if (end_ns <= start_ns)
		return;

	duration_ns = end_ns - start_ns;
	bucket = cpa_unwind_bench_bucket(duration_ns);

	pthread_mutex_lock(&unwind_bench_lock);
	if (unwind_bench_stat.enabled) {
		unwind_bench_stat.count++;
		unwind_bench_stat.total_ns += duration_ns;
		if (duration_ns < unwind_bench_stat.min_ns)
			unwind_bench_stat.min_ns = duration_ns;
		if (duration_ns > unwind_bench_stat.max_ns)
			unwind_bench_stat.max_ns = duration_ns;
		if (bucket >= 0)
			unwind_bench_stat.hist[bucket]++;
	}
	pthread_mutex_unlock(&unwind_bench_lock);
}

void cpa_take_unwind_bench_stat(struct cpa_unwind_bench_stat *stat)
{
	bool enabled;

	if (!stat)
		return;

	pthread_mutex_lock(&unwind_bench_lock);
	*stat = unwind_bench_stat;
	if (stat->count == 0)
		stat->min_ns = 0;
	enabled = unwind_bench_stat.enabled;
	cpa_unwind_bench_clear_locked(enabled);
	pthread_mutex_unlock(&unwind_bench_lock);
}

static void cpa_unwind_record_time_reset(void)
{
	pthread_mutex_lock(&record_time_base_lock);
	record_time_base_valid = false;
	record_time_base_sample_ns = 0;
	record_time_base_ms = 0;
	pthread_mutex_unlock(&record_time_base_lock);
}

static uint64_t cpa_record_ms_from_timestamp(struct cli_stackmap *trace_stackmap, uint64_t timestamp_ns)
{
	uint64_t now_record_ms = cli_stackmap_now_record_ms(trace_stackmap);
	uint64_t record_ms = now_record_ms;
	uint64_t delta_ms;

	if (timestamp_ns == 0)
		return now_record_ms;

	pthread_mutex_lock(&record_time_base_lock);
	if (!record_time_base_valid || now_record_ms < record_time_base_ms) {
		record_time_base_sample_ns = timestamp_ns;
		record_time_base_ms = now_record_ms;
		record_time_base_valid = true;
		record_ms = now_record_ms;
		goto out;
	}

	if (timestamp_ns >= record_time_base_sample_ns) {
		delta_ms = (timestamp_ns - record_time_base_sample_ns) / CPA_NS_PER_MS;
		if (delta_ms < CPA_RECORD_DAY_MS && record_time_base_ms + delta_ms < CPA_RECORD_DAY_MS) {
			record_ms = record_time_base_ms + delta_ms;
		}
		goto out;
	}

	delta_ms = (record_time_base_sample_ns - timestamp_ns) / CPA_NS_PER_MS;
	if (delta_ms < CPA_RECORD_DAY_MS && delta_ms <= record_time_base_ms)
		record_ms = record_time_base_ms - delta_ms;

out:
	pthread_mutex_unlock(&record_time_base_lock);
	return record_ms;
}

static void cpa_kernel_symbol_cache_clear_locked(void)
{
	struct cpa_kernel_symbol_cache_entry *entry = NULL;
	struct cpa_kernel_symbol_cache_entry *tmp = NULL;

	HASH_ITER (hh, kernel_symbol_cache, entry, tmp) {
		HASH_DEL(kernel_symbol_cache, entry);
		free(entry);
	}
}

static void cpa_kernel_symbol_cache_clear(void)
{
	pthread_mutex_lock(&kernel_symbol_cache_lock);
	cpa_kernel_symbol_cache_clear_locked();
	pthread_mutex_unlock(&kernel_symbol_cache_lock);
}

static int cpa_resolve_kernel_symbol_slow(unsigned long addr, char *buf, size_t len)
{
	FILE *file = NULL;
	unsigned long sym_addr = 0;
	unsigned long best_addr = 0;
	char sym_type = '\0';
	char sym_name[256] = { 0 };
	char best_name[256] = { 0 };
	int ret = -ENOENT;

	file = fopen("/proc/kallsyms", "r");
	if (!file)
		goto out;

	while (fscanf(file, "%lx %c %255s%*[\n]", &sym_addr, &sym_type, sym_name) == 3) {
		if (sym_addr > addr && best_name[0] != '\0')
			break;
		if (sym_addr <= addr) {
			best_addr = sym_addr;
			snprintf(best_name, sizeof(best_name), "%s", sym_name);
		}
	}

	if (best_name[0] == '\0')
		goto out;

	snprintf(buf, len, "%s_[k]+%lu", best_name, addr - best_addr);
	ret = 0;

out:
	if (file)
		fclose(file);
	if (ret < 0)
		snprintf(buf, len, "0x%lx_[k]", addr);
	return ret;
}

static void cpa_kernel_symbol_cache_insert(unsigned long addr, const char *symbol)
{
	struct cpa_kernel_symbol_cache_entry *entry = NULL;

	if (!symbol)
		return;

	pthread_mutex_lock(&kernel_symbol_cache_lock);

	HASH_FIND(hh, kernel_symbol_cache, &addr, sizeof(addr), entry);
	if (entry) {
		pthread_mutex_unlock(&kernel_symbol_cache_lock);
		return;
	}

	if ((unsigned int)HASH_COUNT(kernel_symbol_cache) >= CPA_KERNEL_SYMBOL_CACHE_MAX) {
		pthread_mutex_unlock(&kernel_symbol_cache_lock);
		return;
	}

	entry = calloc(1, sizeof(*entry));
	if (!entry) {
		pthread_mutex_unlock(&kernel_symbol_cache_lock);
		return;
	}

	entry->addr = addr;
	snprintf(entry->symbol, sizeof(entry->symbol), "%s", symbol);
	HASH_ADD(hh, kernel_symbol_cache, addr, sizeof(entry->addr), entry);

	pthread_mutex_unlock(&kernel_symbol_cache_lock);
}

static void cpa_resolve_kernel_symbol(unsigned long addr, char *buf, size_t len)
{
	struct cpa_kernel_symbol_cache_entry *entry = NULL;

	pthread_mutex_lock(&kernel_symbol_cache_lock);
	HASH_FIND(hh, kernel_symbol_cache, &addr, sizeof(addr), entry);
	if (entry) {
		snprintf(buf, len, "%s", entry->symbol);
		pthread_mutex_unlock(&kernel_symbol_cache_lock);
		return;
	}
	pthread_mutex_unlock(&kernel_symbol_cache_lock);

	cpa_resolve_kernel_symbol_slow(addr, buf, len);
	cpa_kernel_symbol_cache_insert(addr, buf);
}

static bool init_unwinder_context(void)
{
	struct gu_context *new_ctx = gu_init(&gu_init_cfg);
	if (!new_ctx) {
		CLI_ERROR("Failed to initialize unwinder context");
		return false;
	}

	unwinder_worker.worker_ctx = new_ctx;
	gu_ctx = new_ctx;
	unwinder_configured = true;

	return true;
}

/**
 * Initialize and (re)configure unwinder context from CLI options.
 */
static enum cpa_worker_init_result cpa_unwinder_init(void *cli_ctx, void *worker_ctx)
{
	if (cpa_kernel_only_fastpath_requested(cli_ctx)) {
		cpa_unwind_bench_reset(false);
		return CPA_INIT_SKIP;
	}

	atomic_init(&accept_events, false);
	cpa_unwind_record_time_reset();
	cpa_unwind_bench_reset(atoi(get_arg_by_name(cli_ctx, "bench")) != 0);
	unwinder_configured = false;
	unwinder_worker.worker_ctx = NULL;
	gu_ctx = NULL;
	gu_init_cfg.go_not_strip_name = atoi(get_arg_by_name(cli_ctx, "strip_name_disable"));
	include_full_path = atoi(get_arg_by_name(cli_ctx, "include_full_path"));
	disable_sym = atoi(get_arg_by_name(cli_ctx, "disable_sym"));
	int pid = atoi(get_arg_by_name(cli_ctx, "pid"));

	queue_size = atoi(get_arg_by_name(cli_ctx, "max_queue_size"));
	queue_size = queue_size < MIN_QUEUE_SIZE ? MIN_QUEUE_SIZE : queue_size;

	queue_init(&stack_queue, queue_size);
	queue_init(&pid_exit_queue, 32768);

	init_drop_policy(queue_size);

	if (!init_unwinder_context()) {
		unwinder_configured = false;
		return CPA_INIT_FAILED;
	}

	if (pid) {
		CLI_OUTPUT("preload debug info for pid %d.", pid);
		gu_preload_pid_debug_info(gu_ctx, pid);
		CLI_OUTPUT("preload debug info done.", pid);
	}

	atomic_store_explicit(&accept_events, true, memory_order_release);

	return CPA_INIT_SUCCESS;
}

struct gu_statistics gu_stats = { 0 };

/**
 * Return libgunwinder stats snapshot copied into static cache.
 */
struct gu_statistics *cpa_get_gunwinder_stat(void)
{
	if (!unwinder_worker.worker_ctx)
		return &gu_stats;
	struct gu_statistics *stats = gu_get_statistics(unwinder_worker.worker_ctx);
	memcpy(&gu_stats, stats, sizeof(struct gu_statistics));

	return &gu_stats;
}

static void cpa_unwinder_destroy(void *worker_ctx)
{
	(void)worker_ctx;
	struct stack_sample *sample = NULL;
	unwinder_configured = false;
	while (1) {
		pthread_mutex_lock(&stack_queue_lock);
		sample = queue_pop(&stack_queue);
		pthread_mutex_unlock(&stack_queue_lock);

		if (!sample)
			break;

		free(sample);
	}

	struct exit_event *exit_event = NULL;
	while ((exit_event = queue_pop(&pid_exit_queue)) != NULL) {
		free(exit_event);
	}

	gu_cleanup(unwinder_worker.worker_ctx);
	unwinder_worker.worker_ctx = NULL;
	gu_ctx = NULL;
	cpa_kernel_symbol_cache_clear();
}

static pthread_mutex_t restart_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t restart_cond = PTHREAD_COND_INITIALIZER;
static bool restart_requested = false;
static bool main_thread_paused = false;

/**
 * Pause-point synchronization for restart paths.
 *
 * Runtime restart sets restart_requested and waits until the main unwinder loop
 * reaches this safe point. Restore clears the request and wakes the loop.
 */
void cpa_check_restart_loop()
{
	pthread_mutex_lock(&restart_mutex);
	if (restart_requested) {
		main_thread_paused = true;
		pthread_cond_signal(&restart_cond);
		while (restart_requested) {
			pthread_cond_wait(&restart_cond, &restart_mutex);
		}
		main_thread_paused = false;
	}
	pthread_mutex_unlock(&restart_mutex);
}

void cpa_unwinder_restore(void *worker_ctx)
{
	(void)worker_ctx;
	pthread_mutex_lock(&restart_mutex);
	restart_requested = false;
	pthread_cond_broadcast(&restart_cond);
	pthread_mutex_unlock(&restart_mutex);

	if (!unwinder_configured || unwinder_worker.worker_ctx == NULL) {
		CLI_ERROR("Failed to restore unwinder worker, context unavailable");
		return;
	}

	cpa_unwind_record_time_reset();
	atomic_store_explicit(&accept_events, true, memory_order_release);
}

void cpa_unwinder_pause(void *worker_ctx)
{
	(void)worker_ctx;
	atomic_store_explicit(&accept_events, false, memory_order_release);

	/*
	 * Stop accepting events first, then wait for the main worker to park at a
	 * safe point before tearing down and rebuilding libgunwinder context.
	 */
	pthread_mutex_lock(&restart_mutex);
	restart_requested = true;
	while (!main_thread_paused) {
		pthread_cond_wait(&restart_cond, &restart_mutex);
	}
	pthread_mutex_unlock(&restart_mutex);

	reset_drop_policy();
	cpa_unwind_record_time_reset();

	cpa_unwinder_destroy(unwinder_worker.worker_ctx);
	unwinder_configured = false;
	unwinder_worker.worker_ctx = NULL;
	gu_ctx = NULL;

	if (!init_unwinder_context())
		CLI_ERROR("Failed to initialize unwinder context");

	cpa_kernel_symbol_cache_clear();

	return;
}

/**
 * Resolve process environment key for symbolization and filtering.
 */
static char *cpa_get_pid_env(struct gu_context *gu_ctx, struct stack_sample *sample)
{
	char *env_name = NULL, *env_cached = NULL;
	char **record_env_name = NULL;
	int record_env_name_count = 0;

	record_env_name = cpa_get_record_env(&record_env_name_count);

	if (sample->type & STACK_EVENT_KTHREAD) {
		env_name = default_env_name;
	} else if (record_env_name) {
		int env_size = 0;
		env_cached = gu_get_pid_private_info(gu_ctx, sample->pid, &env_size);
		if (env_cached) {
			env_name = env_cached;
		} else {
			env_name = get_env_var_by_pid(sample->pid, record_env_name, record_env_name_count);
			if (env_name)
				gu_set_pid_private_info(gu_ctx, sample->pid, env_name, strlen(env_name) + 1);
			else
				gu_set_pid_private_info(gu_ctx, sample->pid, default_env_name, strlen(default_env_name) + 1);
		}
	}

	if (!env_name)
		env_name = default_env_name;

	return env_name;
}

static void cpa_free_env_string(char *env_str)
{
	if (env_str && env_str != default_env_name)
		free(env_str);
}

static char *cpa_get_event_env_name(const struct stack_event *event)
{
	char *env_name = NULL;
	char **record_env_name = NULL;
	int record_env_name_count = 0;

	record_env_name = cpa_get_record_env(&record_env_name_count);
	if ((event->type & STACK_EVENT_KTHREAD) || !record_env_name)
		return default_env_name;

	env_name = get_env_var_by_pid(event->pid, record_env_name, record_env_name_count);
	if (!env_name)
		return default_env_name;

	return env_name;
}

static unsigned long cpa_stack_count_from_event(const struct stack_event *event, unsigned int sample_freq)
{
	unsigned long count = 1;

	if (event->type & STACK_EVENT_IRQOFF)
		count = (event->diff_ns / (1000 * 1000 * 1000 / sample_freq)) + 1;

	return count;
}

#define FRAME_NAME_BUF_SIZE (4096 + 1024)
static char frame_name_buf[FRAME_NAME_BUF_SIZE];
/**
 * Append one symbolized user frame to the shared tracemap.
 */
static void process_single_frame_p(const struct gu_frame_record *frame, void *cb_ctx)
{
	struct cli_stackmap *trace_stackmap = (struct cli_stackmap *)cb_ctx;

	if (disable_sym) {
		if (!frame->elf_info)
			snprintf(frame_name_buf, FRAME_NAME_BUF_SIZE, "0x%lx [%s]", frame->pc, "anon exec segment");
		else
			snprintf(frame_name_buf, FRAME_NAME_BUF_SIZE, "0x%lx [%s]", frame->pc, frame->elf_info->elf_file_path);
		cli_stackmap_append(trace_stackmap, frame_name_buf);
		return;
	}

	if (!frame->elf_info) {
		snprintf(frame_name_buf, FRAME_NAME_BUF_SIZE, "0x%lx [%s]", frame->pc, "anon exec segment");
		cli_stackmap_append(trace_stackmap, frame_name_buf);
		return;
	}

	char *elf_file_split_pid = NULL;

	if (include_full_path && frame->elf_info->elf_file_path != NULL) {
		elf_file_split_pid = strstr(frame->elf_info->elf_file_path, "/root");
		if (elf_file_split_pid)
			elf_file_split_pid += (sizeof("/root") - 1);
		else
			elf_file_split_pid = frame->elf_info->elf_file_path;
	}

	if (!frame->symbol) {
		if (include_full_path && frame->elf_info->elf_file_path != NULL)
			snprintf(frame_name_buf, FRAME_NAME_BUF_SIZE, "0x%lx [%s]", frame->pc, elf_file_split_pid);
		else
			snprintf(frame_name_buf, FRAME_NAME_BUF_SIZE, "0x%lx [%s]", frame->pc, frame->elf_info->base_name);
		cli_stackmap_append(trace_stackmap, frame_name_buf);
	} else {
		if (include_full_path && frame->elf_info->elf_file_path != NULL) {
			snprintf(frame_name_buf, FRAME_NAME_BUF_SIZE, "%s [%s]", frame->symbol, elf_file_split_pid);
			cli_stackmap_append(trace_stackmap, frame_name_buf);
		} else {
			cli_stackmap_append(trace_stackmap, frame->symbol);
		}
	}
}

static char irqoff_sample[64] = { 0 };
static char single_ksym[256] = { 0 };

static unsigned long last_sample_ts = 0;

struct unwinder_stat unwind_stat = { 0 };

void cpa_get_unwinder_stat(struct unwinder_stat *stat)
{
	pthread_mutex_lock(&unwind_stat_lock);
	*stat = unwind_stat;
	pthread_mutex_unlock(&unwind_stat_lock);
}

static void cpa_handle_pid_exit_events(unsigned long sample_ts)
{
	struct exit_event *exit_event = NULL;

	if (sample_ts == 0 || !gu_ctx)
		return;

	while ((exit_event = queue_peek(&pid_exit_queue)) != NULL && exit_event->exit_ts < sample_ts) {
		exit_event = queue_pop(&pid_exit_queue);
		gu_event_occur(gu_ctx, GU_EVENT_PROCESS_EXIT, &exit_event->pid);
		free(exit_event);
	}
}

static void cpa_finish_unwind_sample(struct stack_sample *sample)
{
	int pending_queue_size = 0;

	if (!sample)
		return;

	last_sample_ts = 0;
	cpa_unwind(sample);
	last_sample_ts = sample->timestamp;

	free(sample);

	pending_queue_size = queue_count(&stack_queue);

	pthread_mutex_lock(&unwind_stat_lock);
	unwind_stat.stack_queue_len = pending_queue_size;
	pthread_mutex_unlock(&unwind_stat_lock);

	update_drop_policy_queue_len(pending_queue_size);
	cpa_handle_pid_exit_events(last_sample_ts);
}

void cpa_emit_kernel_only_sample(const struct stack_event *event, unsigned int sample_freq)
{
	struct cli_stackmap *trace_stackmap = NULL;
	char *env_name = NULL;
	char group_comm[TASK_COMM_LEN] = { 0 };

	if (!event)
		return;

	if (event->type & STACK_EVENT_KTHREAD)
		snprintf(group_comm, sizeof(group_comm), "%s", "[kernel]");
	else
		memcpy(group_comm, event->group_comm, sizeof(group_comm));

	env_name = cpa_get_event_env_name(event);
	generate_metadata(cpa_base_info, CPA_BASE_INFO_LEN, (char *)event->comm, group_comm, event->cgid, event->cpu, event->pid, env_name);

	trace_stackmap = cpa_main_tracemap_get_and_lock();

	cli_stackmap_append(trace_stackmap, cpa_base_info);
	cli_stackmap_entry_reverse_ids(trace_stackmap);

	if (event->type & STACK_EVENT_IRQOFF) {
		snprintf(irqoff_sample, sizeof(irqoff_sample), "<# IRQOFF SAMPLE ON CPU %d #>", event->cpu);
		cli_stackmap_append(trace_stackmap, irqoff_sample);
		cli_stackmap_entry_reverse_ids(trace_stackmap);
	}

	if (!event->user_mode && event->kstack_sz == 0)
		cli_stackmap_append(trace_stackmap, "kernel_drop_stack_[k]");

	for (int i = 0; i < event->kstack_sz && i < MAX_KERNEL_STACK_LEVEL; i++) {
		cpa_resolve_kernel_symbol(event->kstack[i], single_ksym, sizeof(single_ksym));
		cli_stackmap_append(trace_stackmap, single_ksym);
	}

	cli_stackmap_entry_reverse_ids(trace_stackmap);
	cli_stackmap_done_at(trace_stackmap, cpa_stack_count_from_event(event, sample_freq), cpa_record_ms_from_timestamp(trace_stackmap, event->timestamp));

	cpa_main_tracemap_unlock();
	cpa_free_env_string(env_name);
}

/**
 * Build and emit one complete stacktrace for a sample to tracemap.
 */
static void cpa_unwind(struct stack_sample *sample)
{
	bool backtrace_user = true;

	if (!sample)
		return;

	int backtrace_ret = GU_UNWIND_REASON_OK;

	char *env_name = cpa_get_pid_env(gu_ctx, sample);
	generate_metadata(cpa_base_info, CPA_BASE_INFO_LEN, sample->comm, sample->group_comm, sample->cgid, sample->cpu, sample->pid, env_name);

	struct cli_stackmap *trace_stackmap = cpa_main_tracemap_get_and_lock();

	cli_stackmap_append(trace_stackmap, cpa_base_info);
	cli_stackmap_entry_reverse_ids(trace_stackmap);

	if (sample->type & STACK_EVENT_KTHREAD || sample->type & STACK_EVENT_DROP_BY_PRESSURE || should_drop_sample() == DROP_SAMPLE_RESULT_FULL_DROP || !cpa_env_should_parse(env_name)) {
		backtrace_user = false;
		if (should_drop_sample() == DROP_SAMPLE_RESULT_FULL_DROP) {
			cli_stackmap_append(trace_stackmap, "<# PRESSURE FULL DROP SAMPLE #>");
			cli_stackmap_entry_reverse_ids(trace_stackmap);
		} else if (sample->type & STACK_EVENT_DROP_BY_PRESSURE) {
			cli_stackmap_append(trace_stackmap, "<# PRESSURE HIGH DROP SAMPLE #>");
			cli_stackmap_entry_reverse_ids(trace_stackmap);
		}
	}

	if (sample->type & STACK_EVENT_IRQOFF) {
		snprintf(irqoff_sample, sizeof(irqoff_sample), "<# IRQOFF SAMPLE ON CPU %d #>", sample->cpu);
		cli_stackmap_append(trace_stackmap, irqoff_sample);
		cli_stackmap_entry_reverse_ids(trace_stackmap);
	}

	if (sample->type & STACK_EVENT_OFFCPU) {
		char buf[32];
		snprintf(buf, sizeof(buf), "<# OFFCPU SAMPLE: (%c) #>", sample->state);
		cli_stackmap_append(trace_stackmap, buf);
		cli_stackmap_entry_reverse_ids(trace_stackmap);
	}

	if (backtrace_user) {
		uint8_t unwind_regs_snapshot[CPA_UNWIND_REGS_SNAPSHOT_SIZE];
		struct cpa_unwind_state unwind_state;
		bool unwind_state_saved;
		bool run_final_unwind = true;
		bool use_fp = false;
		uint64_t bench_start_ns = 0;

		/* direct disable fp unwind, we capture both type(fp,dwarf). */
		gu_flags_clear(sample->info, GU_FLAG_HINT_SET_FP);
		unwind_state_saved = cpa_unwind_state_save(&unwind_state, sample->info, unwind_regs_snapshot, sizeof(unwind_regs_snapshot));

		pthread_mutex_lock(&unwind_stat_lock);
		unwind_stat.sample_backtrace_times_dwarf++;
		unwind_stat.sample_backtrace_times++;
		pthread_mutex_unlock(&unwind_stat_lock);

		// stackmap current level without stack trace
		int no_stack_index = cli_stackmap_current_length(trace_stackmap);

		cpa_debug_dump_sample(sample);

		if (unwind_state_saved) {
			bench_start_ns = cpa_unwind_bench_start();
			gu_unwind(gu_ctx, sample->info, process_single_frame_p, trace_stackmap);

			int backtrace_level = cli_stackmap_current_length(trace_stackmap) - no_stack_index;
			use_fp = sample->info->ustack_fp_level > backtrace_level;

			if (cpa_unwind_state_restore(sample->info, &unwind_state)) {
				cli_stackmap_current_reset(trace_stackmap, no_stack_index);
			} else {
				run_final_unwind = false;
				use_fp = false;
			}

			if (!run_final_unwind)
				cpa_unwind_bench_record(bench_start_ns);
		}

		if (run_final_unwind) {
			if (use_fp) {
				gu_flags_set(sample->info, GU_FLAG_HINT_SET_FP);
				pthread_mutex_lock(&unwind_stat_lock);
				unwind_stat.sample_backtrace_times_fp_better++;
				unwind_stat.sample_backtrace_times++;
				pthread_mutex_unlock(&unwind_stat_lock);
			} else {
				gu_flags_clear(sample->info, GU_FLAG_HINT_SET_FP);
			}

			if (use_fp) {
				gu_unwind(gu_ctx, sample->info, process_single_frame_p, trace_stackmap);
			} else {
				if (!bench_start_ns)
					bench_start_ns = cpa_unwind_bench_start();

				gu_unwind(gu_ctx, sample->info, process_single_frame_p, trace_stackmap);
				cpa_unwind_bench_record(bench_start_ns);
			}
		}

		// add final stop reason
		backtrace_ret = gu_flags_reason(sample->info->flags);
		if (backtrace_ret == GU_UNWIND_REASON_PROCESS_EXIT || backtrace_ret == GU_UNWIND_REASON_LANG_SKIP)
			cli_stackmap_append(trace_stackmap, stop_reason_str[backtrace_ret]);

		cli_stackmap_entry_reverse_ids(trace_stackmap);
	}

	if (!sample->user_mode && sample->kstack_fp_level == 0)
		cli_stackmap_append(trace_stackmap, "kernel_drop_stack_[k]");

	for (int i = 0; i < sample->kstack_fp_level; i++) {
		if (sample->kstack_fp[i] == ALREADY_RESTORE_FLAG) {
			cli_stackmap_append(trace_stackmap, "<#ALREADY RESTORE#>");
			continue;
		}

		uint64_t off = 0;
		char sym_buf[256];

		if (gu_search_kernel_symbol(gu_ctx, sample->kstack_fp[i], sym_buf, sizeof(sym_buf), &off) == 0)
			snprintf(single_ksym, sizeof(single_ksym), "%s_[k]+%llu", sym_buf, (unsigned long long)off);
		else
			snprintf(single_ksym, sizeof(single_ksym), "0x%lx_[k]", sample->kstack_fp[i]);
		cli_stackmap_append(trace_stackmap, single_ksym);
	}

	cli_stackmap_entry_reverse_ids(trace_stackmap);
	cli_stackmap_done_at(trace_stackmap, sample->stack_count, cpa_record_ms_from_timestamp(trace_stackmap, sample->timestamp));

	cpa_main_tracemap_unlock();

	cpa_free_env_string(env_name);

	return;
}

int cpa_add_pid_exit_event(struct exit_event *exit)
{
	if (!exit)
		return -1;

	if (!atomic_load_explicit(&accept_events, memory_order_acquire))
		return -1;

	return queue_push(&pid_exit_queue, exit);
}

/**
 * Trigger symbol table reload event for module update notifications.
 */
void cpa_add_ksyms_reload_event(void)
{
	cpa_kernel_symbol_cache_clear();

	if (!atomic_load_explicit(&accept_events, memory_order_acquire) || !gu_ctx)
		return;

	gu_event_occur(gu_ctx, GU_EVENT_MODULE_RELOAD, NULL);
}

int cpa_add_stack_event(struct stack_sample *sample)
{
	if (!sample)
		return -1;
	if (!atomic_load_explicit(&accept_events, memory_order_acquire))
		return -1;
	pthread_mutex_lock(&stack_queue_lock);
	int ret = queue_push(&stack_queue, sample);
	pthread_mutex_unlock(&stack_queue_lock);
	return ret;
}

void cpa_unwinder_drain_pending(void)
{
	struct stack_sample *sample = NULL;

	if (!unwinder_configured || unwinder_worker.worker_ctx == NULL)
		return;

	while (1) {
		pthread_mutex_lock(&stack_queue_lock);
		sample = queue_pop(&stack_queue);
		pthread_mutex_unlock(&stack_queue_lock);

		if (!sample)
			break;

		cpa_finish_unwind_sample(sample);
	}
}

/**
 * Consume samples, unwind when ready, and drain stale process-exit events.
 */
void cpa_unwind_main_worker_fn(void *worker_ctx)
{
	(void)worker_ctx;
	struct stack_sample *sample = NULL;
	while (1) {
		pthread_mutex_lock(&stack_queue_lock);
		sample = queue_pop(&stack_queue);
		pthread_mutex_unlock(&stack_queue_lock);

		if (sample)
			break;

		/*
		 * Only sleep when the queue is empty. This keeps restart/shutdown
		 * responsive without spinning while there is no work to consume.
		 */
		cpa_check_restart_loop();
		usleep(1000);
		if (should_stop())
			break;
	}

	if (should_stop()) {
		if (sample)
			free(sample);
		return;
	}

	cpa_finish_unwind_sample(sample);
}

/**
 * Unwinder worker registration for runtime startup.
 */
struct cpa_worker unwinder_worker = {
	.worker_name = "unwinder_worker",
	.worker_ctx = NULL,
	// highest priority
	.worker_index = 0,

	.init_fn = cpa_unwinder_init,
	.destroy_fn = cpa_unwinder_destroy,
	.pause_fn = cpa_unwinder_pause,
	.restore_fn = cpa_unwinder_restore,
	.timer_fn = NULL,
	.main_worker_fn = cpa_unwind_main_worker_fn,
};
