// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "cpa_unwinder.h"
#include "cpa_sample_pool.h"
#include "cpa_target_ctl.h"
#include "cpa_exit_env.h"
#include "cli_stackmap.h"
#include "cli_stackmap_private.h"
#include "cpa_capture_mode.h"
#include "cpa_env.h"
#include "cli_profile_metadata.h"
#include "cpa_drop_policy.h"
#include "cpa_runtime.h"
#include "cpa_debug.h"
#include "cpa_unwind_state.h"
#include "cpa_unwind_queue.h"
#include "cpa_frames.h"
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
#include <unistd.h>
#include <sys/wait.h>

/**
 * @file cpa_unwinder.c
 * @brief Implements the unwinder worker for cpa.
 *
 * This worker manages the lifecycle of the unwinder library,
 * including initialization, cleanup, and re-initialization on pause.
 */

static pthread_mutex_t unwind_stat_lock = PTHREAD_MUTEX_INITIALIZER;

static char default_env_name[] = "SYSTEM";

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

struct cpa_worker unwinder_worker;

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
		1ULL * CPA_NS_PER_US, 4ULL * CPA_NS_PER_US, 16ULL * CPA_NS_PER_US, 64ULL * CPA_NS_PER_US, 256ULL * CPA_NS_PER_US, 512ULL * CPA_NS_PER_US, 1024ULL * CPA_NS_PER_US, 2048ULL * CPA_NS_PER_US, 4096ULL * CPA_NS_PER_US, UINT64_MAX,
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

/*
 * Samples are unwound by --unwind_workers threads.  Worker 0 is the main
 * thread's runtime loop (CPA_MAIN_WORKER); workers 1..N-1 are threads of
 * their own, started at init and kept across pause/restore.  Each worker
 * owns one queue lane and one libgunwinder context: a process (tgid) is
 * always unwound by the worker of its lane, so its state in that context
 * has one writer.  Kernel symbols are loaded by context 0 only
 * (CPA_KERNEL_SYMBOLS_CTX) and looked up through it by every worker.
 *
 * A worker builds the frames of a sample in its own buffer without a lock,
 * then takes the trace map lock once to commit them.
 */
#define FRAME_NAME_BUF_SIZE (4096 + 1024)

struct unwind_worker {
	unsigned int index;
	struct gu_context *ctx;
	struct cpa_frames frames;
	char frame_buf[FRAME_NAME_BUF_SIZE];
	char base_info[CPA_BASE_INFO_LEN];
	/* the sample being unwound is a crash or an exit: crash-level frames */
	bool verbose_frames;
	/* when the next queued exit of the lane may be ready, 0 = none */
	uint64_t exit_deadline_ns;
	struct exit_event *exit_batch[CPA_PID_EXIT_DRAIN_BATCH];
	pthread_t thread;
	bool thread_started;
};

static struct unwind_worker workers[CPA_UNWIND_LANES_MAX];
static unsigned int worker_count = 1;
/*
 * Publishing contexts: a pause replaces them, the timer thread reloads
 * kernel symbols and reads statistics.  Never taken on a worker's unwind
 * path: workers use their own context, which only an accepted pause (all
 * workers parked) replaces.
 */
static pthread_mutex_t gu_ctx_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * The pause handshake.  A pause sets restart_requested and wakes every
 * lane; each worker parks in cpa_check_restart_loop().  The pause owns the
 * contexts and the queue once all worker_count workers are parked (or
 * stopped, see workers_quiesced).
 */
static pthread_mutex_t restart_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t restart_cond = PTHREAD_COND_INITIALIZER;
static bool restart_requested;
static unsigned int workers_parked;
/* aux workers leave their loop (stop, or a failed init) */
static atomic_bool aux_quit;
/*
 * Aux workers start at the unwinder's init, before the workers initialized
 * after it (debug dump, env...) have set their state: they wait here until
 * worker 0's first round, which runs only once every worker is initialized.
 */
static bool workers_go;
/*
 * No worker holds a sample: set by an accepted pause until restore, and for
 * good once stop has joined the aux workers (worker 0 is the main thread,
 * out of its loop by then).  Only then may another thread unwind queued
 * samples with the workers' contexts and buffers.
 */
static bool workers_quiesced;

static struct gu_context *kernel_symbols_ctx(void)
{
	return workers[CPA_KERNEL_SYMBOLS_CTX].ctx;
}

static struct unwind_worker *owner_of(uint32_t tgid)
{
	return &workers[cpa_unwind_lane_of(tgid)];
}

static void contexts_destroy(void)
{
	for (unsigned int i = 0; i < worker_count; i++) {
		gu_cleanup(workers[i].ctx);
		workers[i].ctx = NULL;
	}
}

static bool contexts_create(void)
{
	for (unsigned int i = 0; i < worker_count; i++) {
		struct gu_init_cfg cfg = gu_init_cfg;

		cfg.no_kernel_symbols = i != CPA_KERNEL_SYMBOLS_CTX;
		workers[i].ctx = gu_init(&cfg);
		if (!workers[i].ctx) {
			CLI_ERROR("Failed to initialize unwinder context %u", i);
			contexts_destroy();
			return false;
		}
	}
	return true;
}

static void *aux_worker_main(void *arg);

static void aux_workers_join(void)
{
	atomic_store(&aux_quit, true);
	pthread_mutex_lock(&restart_mutex);
	pthread_cond_broadcast(&restart_cond);
	pthread_mutex_unlock(&restart_mutex);
	cpa_unwind_queue_kick();
	for (unsigned int i = 1; i < worker_count; i++) {
		if (!workers[i].thread_started)
			continue;
		pthread_join(workers[i].thread, NULL);
		workers[i].thread_started = false;
	}
}

static int aux_workers_start(void)
{
	atomic_store(&aux_quit, false);
	workers_go = false;
	for (unsigned int i = 1; i < worker_count; i++) {
		int err = pthread_create(&workers[i].thread, NULL, aux_worker_main, &workers[i]);

		if (err) {
			CLI_ERROR("Failed to start unwind worker %u: %s", i, strerror(err));
			aux_workers_join();
			return -err;
		}
		workers[i].thread_started = true;
	}
	return 0;
}

static void preload_target_pid(int pid)
{
	if (pid <= 0)
		return;
	CLI_OUTPUT("preload debug info for pid %d.", pid);
	pthread_mutex_lock(&gu_ctx_lock);
	gu_preload_pid_debug_info(owner_of((uint32_t)pid)->ctx, pid);
	pthread_mutex_unlock(&gu_ctx_lock);
	CLI_OUTPUT("preload debug info done.");
}

int cpa_unwind_workers_validate(void *cli_ctx)
{
	const char *value = get_arg_by_name(cli_ctx, "unwind_workers");
	unsigned int max = cpa_unwind_workers_max();
	unsigned int n;

	if (cpa_unwind_workers_parse(value, max, &n) == 0)
		return 0;
	CLI_ERROR("--unwind_workers must be an integer from 1 to %u (the online CPUs, at most %d), got '%s'", max,
		  CPA_UNWIND_LANES_MAX, value);
	return -EINVAL;
}

/**
 * Initialize and (re)configure unwinder context from CLI options.
 */
static enum cpa_worker_init_result cpa_unwinder_init(void *cli_ctx, void *worker_ctx)
{
	unsigned int count = 1;

	(void)worker_ctx;
	if (cpa_kernel_only_fastpath_requested(cli_ctx)) {
		cpa_unwind_bench_reset(false);
		return CPA_INIT_SKIP;
	}

	cpa_unwind_record_time_reset();
	cpa_unwind_bench_reset(atoi(get_arg_by_name(cli_ctx, "bench")) != 0);
	unwinder_worker.worker_ctx = NULL;
	gu_init_cfg.go_not_strip_name = atoi(get_arg_by_name(cli_ctx, "strip_name_disable"));
	include_full_path = atoi(get_arg_by_name(cli_ctx, "include_full_path"));
	disable_sym = atoi(get_arg_by_name(cli_ctx, "disable_sym"));
	if (cpa_unwind_workers_parse(get_arg_by_name(cli_ctx, "unwind_workers"), cpa_unwind_workers_max(), &count)) {
		CLI_ERROR("invalid --unwind_workers");
		return CPA_INIT_FAILED;
	}

	queue_size = atoi(get_arg_by_name(cli_ctx, "max_queue_size"));
	queue_size = queue_size < MIN_QUEUE_SIZE ? MIN_QUEUE_SIZE : queue_size;

	worker_count = count;
	workers_parked = 0;
	restart_requested = false;
	workers_quiesced = false;
	for (unsigned int i = 0; i < worker_count; i++) {
		memset(&workers[i], 0, sizeof(workers[i]));
		workers[i].index = i;
		cpa_frames_init(&workers[i].frames);
	}

	if (cpa_unwind_queue_init(queue_size, worker_count))
		return CPA_INIT_FAILED;
	if (!contexts_create()) {
		cpa_unwind_queue_cleanup(true);
		return CPA_INIT_FAILED;
	}
	unwinder_worker.worker_ctx = workers[CPA_MAIN_WORKER].ctx;

	preload_target_pid(atoi(get_arg_by_name(cli_ctx, "pid")));

	if (aux_workers_start()) {
		contexts_destroy();
		cpa_unwind_queue_cleanup(true);
		unwinder_worker.worker_ctx = NULL;
		return CPA_INIT_FAILED;
	}
	if (worker_count > 1)
		CLI_OUTPUT("unwind workers: %u", worker_count);

	cpa_unwind_queue_set_accepting(true);
	return CPA_INIT_SUCCESS;
}

struct gu_statistics gu_stats = { 0 };

/**
 * Return libgunwinder stats summed over the worker contexts.
 */
struct gu_statistics *cpa_get_gunwinder_stat(void)
{
	struct gu_statistics sum = { 0 };

	pthread_mutex_lock(&gu_ctx_lock);
	for (unsigned int i = 0; i < worker_count; i++) {
		struct gu_statistics one;
		uint64_t *dst = (uint64_t *)&sum;
		const uint64_t *src = (const uint64_t *)&one;

		if (!workers[i].ctx || gu_copy_statistics(workers[i].ctx, &one))
			continue;
		/* every field is a uint64_t counter or gauge */
		for (size_t f = 0; f < sizeof(sum) / sizeof(uint64_t); f++)
			dst[f] += src[f];
	}
	pthread_mutex_unlock(&gu_ctx_lock);
	gu_stats = sum;
	return &gu_stats;
}

/*
 * Stop: the aux workers finish the sample in hand and are joined, before
 * any worker is destroyed: the store worker's last flush (destroyed first)
 * must not race a worker still writing to the trace map.  Worker 0 is the
 * main thread, already out of the runtime loop.
 */
static void cpa_unwinder_stop(void *worker_ctx)
{
	(void)worker_ctx;
	cpa_unwind_queue_set_accepting(false);
	aux_workers_join();
	pthread_mutex_lock(&restart_mutex);
	workers_quiesced = true;
	pthread_mutex_unlock(&restart_mutex);
}

static void cpa_unwinder_destroy(void *worker_ctx)
{
	(void)worker_ctx;
	/* idempotent: also the path of a failed runtime start */
	cpa_unwinder_stop(NULL);
	cpa_unwind_queue_cleanup(true);
	pthread_mutex_lock(&gu_ctx_lock);
	contexts_destroy();
	pthread_mutex_unlock(&gu_ctx_lock);
	for (unsigned int i = 0; i < worker_count; i++)
		cpa_frames_destroy(&workers[i].frames);
	unwinder_worker.worker_ctx = NULL;
	cpa_kernel_symbol_cache_clear();
}

/**
 * Pause point of a worker: park while a restart is requested.
 */
void cpa_check_restart_loop(void)
{
	pthread_mutex_lock(&restart_mutex);
	if (restart_requested) {
		workers_parked++;
		pthread_cond_broadcast(&restart_cond);
		while (restart_requested)
			pthread_cond_wait(&restart_cond, &restart_mutex);
		workers_parked--;
	}
	pthread_mutex_unlock(&restart_mutex);
}

void cpa_unwinder_restore(void *worker_ctx)
{
	(void)worker_ctx;
	pthread_mutex_lock(&restart_mutex);
	restart_requested = false;
	if (!should_stop())
		workers_quiesced = false;
	pthread_cond_broadcast(&restart_cond);
	pthread_mutex_unlock(&restart_mutex);

	if (!workers[CPA_MAIN_WORKER].ctx) {
		CLI_ERROR("Failed to restore unwinder worker, context unavailable");
		return;
	}

	cpa_unwind_record_time_reset();
	cpa_unwind_queue_set_accepting(true);
}

/*
 * Runs on the timer thread, never on a worker.  Waits until every worker is
 * parked; a stop during the wait gives up (the workers are leaving, the
 * contexts are kept as they are and freed at destroy).
 */
void cpa_unwinder_pause(void *worker_ctx)
{
	bool accepted;

	(void)worker_ctx;
	cpa_unwind_queue_set_accepting(false);

	pthread_mutex_lock(&restart_mutex);
	restart_requested = true;
	pthread_mutex_unlock(&restart_mutex);
	cpa_unwind_queue_kick();

	pthread_mutex_lock(&restart_mutex);
	while (workers_parked < worker_count && !should_stop()) {
		struct timespec abs;

		clock_gettime(CLOCK_REALTIME, &abs);
		abs.tv_nsec += 100 * 1000 * 1000;
		if (abs.tv_nsec >= 1000000000L) {
			abs.tv_sec++;
			abs.tv_nsec -= 1000000000L;
		}
		pthread_cond_timedwait(&restart_cond, &restart_mutex, &abs);
	}
	accepted = workers_parked == worker_count;
	if (accepted)
		workers_quiesced = true;
	pthread_mutex_unlock(&restart_mutex);

	if (!accepted) {
		CLI_ERROR("unwinder pause abandoned: stopping");
		return;
	}

	reset_drop_policy();
	cpa_unwind_record_time_reset();

	/* what is queued belongs to the contexts about to go: dropped, as ever */
	cpa_unwind_queue_cleanup(false);
	pthread_mutex_lock(&gu_ctx_lock);
	contexts_destroy();
	if (!contexts_create())
		CLI_ERROR("Failed to initialize unwinder context");
	unwinder_worker.worker_ctx = workers[CPA_MAIN_WORKER].ctx;
	pthread_mutex_unlock(&gu_ctx_lock);

	cpa_kernel_symbol_cache_clear();
}

/**
 * Resolve process environment key for symbolization and filtering.
 */
static char *cpa_get_pid_env(struct gu_context *ctx, struct stack_sample *sample)
{
	char *env_name = NULL, *env_cached = NULL;
	char **record_env_name = NULL;
	int record_env_name_count = 0;

	record_env_name = cpa_get_record_env(&record_env_name_count);

	if (sample->type & STACK_EVENT_KTHREAD) {
		env_name = default_env_name;
	} else if (record_env_name) {
		int env_size = 0;
		env_cached = gu_get_pid_private_info(ctx, sample->tgid, &env_size);
		if (env_cached) {
			env_name = env_cached;
		} else {
			env_name = get_env_var_by_pid(sample->tgid, record_env_name, record_env_name_count);
			if (env_name)
				gu_set_pid_private_info(ctx, sample->tgid, env_name, strlen(env_name) + 1);
			else
				gu_set_pid_private_info(ctx, sample->tgid, default_env_name, strlen(default_env_name) + 1);
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

/* A GNU build-id (20 bytes); libgunwinder's MD5 fallback is not one. */
#define CPA_GNU_BUILD_ID_LEN 20

/*
 * " [build-id=<hex>]" for an ELF with a GNU build-id, empty otherwise: the
 * MD5 digest libgunwinder falls back to is a cache key, and `cpa show
 * --list-core` looks build-ids up in /usr/lib/debug/.build-id.
 */
static void format_build_id_suffix(const struct gu_elf_info *elf_info, char *buf, size_t size)
{
	size_t pos;

	buf[0] = '\0';
	if (!elf_info || !elf_info->build_id || elf_info->build_id_len != CPA_GNU_BUILD_ID_LEN)
		return;
	if (size < sizeof(" [build-id=]") + CPA_GNU_BUILD_ID_LEN * 2)
		return;
	pos = snprintf(buf, size, " [build-id=");
	for (int i = 0; i < CPA_GNU_BUILD_ID_LEN; i++)
		pos += snprintf(buf + pos, size - pos, "%02x", elf_info->build_id[i]);
	snprintf(buf + pos, size - pos, "]");
}

/*
 * Crash-level frame of a COREDUMP or EXIT sample: symbol+offset, absolute
 * and file-relative pc, build-id and the full path, so `cpa show
 * --list-core --core-verbose` can resolve it offline.
 */
static void format_verbose_frame(const struct gu_frame_record *frame, char *buf)
{
	char build_id[64];
	const char *path = frame->elf_info ? frame->elf_info->elf_file_path : NULL;

	format_build_id_suffix(frame->elf_info, build_id, sizeof(build_id));
	if (!frame->elf_info)
		snprintf(buf, FRAME_NAME_BUF_SIZE, "0x%lx [pc=0x%lx] [%s]", frame->abs_pc, frame->pc, "anon exec segment");
	else if (!frame->symbol || disable_sym)
		snprintf(buf, FRAME_NAME_BUF_SIZE, "0x%lx [pc=0x%lx]%s [%s]", frame->abs_pc, frame->pc, build_id,
			 path ? path : frame->elf_info->base_name);
	else if (path)
		snprintf(buf, FRAME_NAME_BUF_SIZE, "%s+0x%lx @0x%lx [pc=0x%lx]%s [%s]", frame->symbol, frame->offset,
			 frame->abs_pc, frame->pc, build_id, path);
	else
		snprintf(buf, FRAME_NAME_BUF_SIZE, "%s+0x%lx @0x%lx [pc=0x%lx]%s", frame->symbol, frame->offset,
			 frame->abs_pc, frame->pc, build_id);
}

/**
 * Append one symbolized user frame to the worker's frames.
 */
static void process_single_frame_p(const struct gu_frame_record *frame, void *cb_ctx)
{
	struct unwind_worker *w = cb_ctx;
	char *buf = w->frame_buf;

	if (w->verbose_frames) {
		format_verbose_frame(frame, buf);
		cpa_frames_append(&w->frames, buf);
		return;
	}

	if (disable_sym) {
		if (!frame->elf_info)
			snprintf(buf, FRAME_NAME_BUF_SIZE, "0x%lx [%s]", frame->pc, "anon exec segment");
		else
			snprintf(buf, FRAME_NAME_BUF_SIZE, "0x%lx [%s]", frame->pc, frame->elf_info->elf_file_path);
		cpa_frames_append(&w->frames, buf);
		return;
	}

	if (!frame->elf_info) {
		snprintf(buf, FRAME_NAME_BUF_SIZE, "0x%lx [%s]", frame->pc, "anon exec segment");
		cpa_frames_append(&w->frames, buf);
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
			snprintf(buf, FRAME_NAME_BUF_SIZE, "0x%lx [%s]", frame->pc, elf_file_split_pid);
		else
			snprintf(buf, FRAME_NAME_BUF_SIZE, "0x%lx [%s]", frame->pc, frame->elf_info->base_name);
		cpa_frames_append(&w->frames, buf);
	} else {
		if (include_full_path && frame->elf_info->elf_file_path != NULL) {
			snprintf(buf, FRAME_NAME_BUF_SIZE, "%s [%s]", frame->symbol, elf_file_split_pid);
			cpa_frames_append(&w->frames, buf);
		} else {
			cpa_frames_append(&w->frames, frame->symbol);
		}
	}
}

static const char *cpa_signal_name(int sig)
{
	switch (sig) {
	case 6: return "SIGABRT";
	case 7: return "SIGBUS";
	case 8: return "SIGFPE";
	case 4: return "SIGILL";
	case 11: return "SIGSEGV";
	case 5: return "SIGTRAP";
	default: return "SIG?";
	}
}

struct unwinder_stat unwind_stat = { 0 };

void cpa_get_unwinder_stat(struct unwinder_stat *stat)
{
	pthread_mutex_lock(&unwind_stat_lock);
	*stat = unwind_stat;
	pthread_mutex_unlock(&unwind_stat_lock);
}

/* The exits of @w's lane that are ready: their processes' state goes. */
static void cpa_reap_exits(struct unwind_worker *w)
{
	unsigned int n;

	do {
		n = cpa_unwind_queue_pop_ready_exits(w->index, w->exit_batch, CPA_PID_EXIT_DRAIN_BATCH,
						     &w->exit_deadline_ns);
		for (unsigned int i = 0; i < n; i++) {
			struct exit_event *exit_event = w->exit_batch[i];

			gu_event_occur(w->ctx, GU_EVENT_PROCESS_EXIT, &exit_event->gu);
			cpa_target_on_exit(exit_event->gu.pid);
			cpa_exit_env_on_pid_exit(exit_event->gu.pid, exit_event->gu.start_time);
			free(exit_event);
		}
	} while (n == CPA_PID_EXIT_DRAIN_BATCH);
}

void cpa_emit_kernel_only_sample(const struct stack_event *event, unsigned int sample_freq)
{
	struct cli_stackmap *trace_stackmap = NULL;
	char *env_name = NULL;
	char group_comm[TASK_COMM_LEN] = { 0 };
	char base_info[CPA_BASE_INFO_LEN];
	char irqoff_sample[64];
	char single_ksym[256];

	if (!event)
		return;

	if (event->type & STACK_EVENT_KTHREAD)
		snprintf(group_comm, sizeof(group_comm), "%s", "[kernel]");
	else
		memcpy(group_comm, event->group_comm, sizeof(group_comm));

	env_name = cpa_get_event_env_name(event);
	generate_metadata(base_info, CPA_BASE_INFO_LEN, (char *)event->comm, group_comm, event->cgid, event->cpu, event->pid, env_name);

	trace_stackmap = cpa_main_tracemap_get_and_lock();

	cli_stackmap_append(trace_stackmap, base_info);
	cli_stackmap_entry_reverse_ids(trace_stackmap);

	if (event->type & STACK_EVENT_IRQOFF) {
		snprintf(irqoff_sample, sizeof(irqoff_sample), "<# IRQOFF SAMPLE ON CPU %d #>", event->cpu);
		cli_stackmap_append(trace_stackmap, irqoff_sample);
		cli_stackmap_entry_reverse_ids(trace_stackmap);
	}

	/* a lite BPF object sends a stack id instead of the stack */
	const unsigned long *kstack = event->kstack;
	unsigned long kstack_by_id[MAX_KERNEL_STACK_LEVEL];
	int kstack_level = event->kstack_sz;

	if (kstack_level == 0 && event->kstack_id >= 0) {
		kstack_level = stack_capture_lookup_kstack(event->kstack_id, kstack_by_id,
							   MAX_KERNEL_STACK_LEVEL);
		kstack = kstack_by_id;
	}

	if (!event->user_mode && kstack_level == 0)
		cli_stackmap_append(trace_stackmap, "kernel_drop_stack_[k]");

	for (int i = 0; i < kstack_level && i < MAX_KERNEL_STACK_LEVEL; i++) {
		cpa_resolve_kernel_symbol(kstack[i], single_ksym, sizeof(single_ksym));
		cli_stackmap_append(trace_stackmap, single_ksym);
	}

	cli_stackmap_entry_reverse_ids(trace_stackmap);
	cli_stackmap_done_at(trace_stackmap, cpa_stack_count_from_event(event, sample_freq), cpa_record_ms_from_timestamp(trace_stackmap, event->timestamp));

	cpa_main_tracemap_unlock();
	cpa_free_env_string(env_name);
}

/* Append and close the marker frames of a sample, as one reversed group. */
static void cpa_frames_marker(struct cpa_frames *frames, const char *marker)
{
	cpa_frames_append(frames, marker);
	cpa_frames_reverse(frames);
}

/**
 * Build one complete stacktrace for a sample in @w's frames, then commit it
 * to the trace map under its lock.
 */
static void cpa_unwind(struct unwind_worker *w, struct stack_sample *sample)
{
	struct cpa_frames *frames = &w->frames;
	struct cli_stackmap *trace_stackmap;
	bool backtrace_user = true;
	int backtrace_ret = GU_UNWIND_REASON_OK;
	char marker[128];

	if (!sample)
		return;

	cpa_frames_clear(frames);
	w->verbose_frames = sample->type & (STACK_EVENT_COREDUMP | STACK_EVENT_EXIT_NONZERO);
	char *env_name = cpa_get_pid_env(w->ctx, sample);
	generate_metadata(w->base_info, CPA_BASE_INFO_LEN, sample->comm, sample->group_comm, sample->cgid, sample->cpu, sample->pid, env_name);

	cpa_frames_marker(frames, w->base_info);

	if (sample->type & STACK_EVENT_KTHREAD || sample->type & STACK_EVENT_DROP_BY_PRESSURE || should_drop_sample() == DROP_SAMPLE_RESULT_FULL_DROP || !cpa_env_should_parse(env_name)) {
		backtrace_user = false;
		if (should_drop_sample() == DROP_SAMPLE_RESULT_FULL_DROP)
			cpa_frames_marker(frames, "<# PRESSURE FULL DROP SAMPLE #>");
		else if (sample->type & STACK_EVENT_DROP_BY_PRESSURE)
			cpa_frames_marker(frames, "<# PRESSURE HIGH DROP SAMPLE #>");
	}

	if (sample->type & STACK_EVENT_IRQOFF) {
		snprintf(marker, sizeof(marker), "<# IRQOFF SAMPLE ON CPU %d #>", sample->cpu);
		cpa_frames_marker(frames, marker);
	}

	if (sample->type & STACK_EVENT_COREDUMP) {
		snprintf(marker, sizeof(marker), "<# COREDUMP %s code=%d #>", cpa_signal_name(sample->signal), sample->signal_code);
		cpa_frames_marker(frames, marker);
	}

	/*
	 * The raw code is the kernel's wait(2) status word: N << 8 for exit(N),
	 * the signal number for a fatal signal, | 0x80 when it dumped core.
	 */
	if (sample->type & STACK_EVENT_EXIT_NONZERO) {
		int raw = sample->signal;

		if (WIFEXITED(raw))
			snprintf(marker, sizeof(marker), "<# EXIT NONZERO raw=%d exit=%d #>", raw, WEXITSTATUS(raw));
		else if (WIFSIGNALED(raw))
			snprintf(marker, sizeof(marker), "<# EXIT NONZERO raw=%d sig=%d core=%d #>", raw, WTERMSIG(raw),
				 WCOREDUMP(raw) ? 1 : 0);
		else
			snprintf(marker, sizeof(marker), "<# EXIT NONZERO raw=%d #>", raw);
		cpa_frames_marker(frames, marker);
	}

	if (sample->type & STACK_EVENT_OFFCPU) {
		snprintf(marker, sizeof(marker), "<# OFFCPU SAMPLE: (%c) #>", sample->state);
		cpa_frames_marker(frames, marker);
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

		// frames so far, without the user stack
		uint32_t no_stack_index = cpa_frames_length(frames);

		cpa_debug_dump_sample(sample);

		if (unwind_state_saved) {
			bench_start_ns = cpa_unwind_bench_start();
			gu_unwind(w->ctx, sample->info, process_single_frame_p, w);

			int backtrace_level = (int)(cpa_frames_length(frames) - no_stack_index);
			use_fp = sample->info->ustack_fp_level > backtrace_level;

			if (cpa_unwind_state_restore(sample->info, &unwind_state)) {
				cpa_frames_reset(frames, no_stack_index);
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
				gu_unwind(w->ctx, sample->info, process_single_frame_p, w);
			} else {
				if (!bench_start_ns)
					bench_start_ns = cpa_unwind_bench_start();

				gu_unwind(w->ctx, sample->info, process_single_frame_p, w);
				cpa_unwind_bench_record(bench_start_ns);
			}
		}

		// add final stop reason
		backtrace_ret = gu_flags_reason(sample->info->flags);
		if (backtrace_ret == GU_UNWIND_REASON_PROCESS_EXIT || backtrace_ret == GU_UNWIND_REASON_LANG_SKIP)
			cpa_frames_append(frames, stop_reason_str[backtrace_ret]);

		cpa_frames_reverse(frames);
	}

	if (!sample->user_mode && sample->kstack_fp_level == 0)
		cpa_frames_append(frames, "kernel_drop_stack_[k]");

	for (int i = 0; i < sample->kstack_fp_level; i++) {
		if (sample->kstack_fp[i] == ALREADY_RESTORE_FLAG) {
			cpa_frames_append(frames, "<#ALREADY RESTORE#>");
			continue;
		}

		uint64_t off = 0;
		char sym_buf[256];

		if (gu_search_kernel_symbol(kernel_symbols_ctx(), sample->kstack_fp[i], sym_buf, sizeof(sym_buf), &off) == 0)
			snprintf(w->frame_buf, FRAME_NAME_BUF_SIZE, "%s_[k]+%llu", sym_buf, (unsigned long long)off);
		else
			snprintf(w->frame_buf, FRAME_NAME_BUF_SIZE, "0x%lx_[k]", sample->kstack_fp[i]);
		cpa_frames_append(frames, w->frame_buf);
	}

	cpa_frames_reverse(frames);

	trace_stackmap = cpa_main_tracemap_get_and_lock();
	cpa_frames_commit(frames, trace_stackmap);
	cli_stackmap_done_at(trace_stackmap, sample->stack_count, cpa_record_ms_from_timestamp(trace_stackmap, sample->timestamp));
	cpa_main_tracemap_unlock();

	cpa_free_env_string(env_name);
}

/* Unwind a popped sample of @w's lane and give it back to the queue. */
static void cpa_finish_unwind_sample(struct unwind_worker *w, struct stack_sample *sample)
{
	unsigned int queued;

	cpa_unwind(w, sample);
	/* the sample is freed here: nothing reads it afterwards */
	cpa_unwind_queue_retire_sample(sample);

	queued = cpa_unwind_queue_sample_len();
	pthread_mutex_lock(&unwind_stat_lock);
	unwind_stat.stack_queue_len = queued;
	pthread_mutex_unlock(&unwind_stat_lock);

	/* pressure counts the samples workers hold, not only the queued ones */
	update_drop_policy_queue_len(cpa_unwind_queue_admitted());
}

/* One round of a worker: reap the ready exits, wait for and unwind a sample. */
static void cpa_worker_step(struct unwind_worker *w)
{
	struct stack_sample *sample;

	cpa_reap_exits(w);
	sample = cpa_unwind_queue_wait_sample(w->index, w->exit_deadline_ns);
	if (!sample)
		return;
	if (should_stop()) {
		cpa_unwind_queue_retire_sample(sample);
		return;
	}
	cpa_finish_unwind_sample(w, sample);
}

static void *aux_worker_main(void *arg)
{
	struct unwind_worker *w = arg;

	pthread_mutex_lock(&restart_mutex);
	while (!workers_go && !atomic_load(&aux_quit) && !should_stop())
		pthread_cond_wait(&restart_cond, &restart_mutex);
	pthread_mutex_unlock(&restart_mutex);

	while (!should_stop() && !atomic_load(&aux_quit)) {
		cpa_check_restart_loop();
		if (should_stop() || atomic_load(&aux_quit))
			break;
		cpa_worker_step(w);
	}
	return NULL;
}

void cpa_add_ksyms_reload_event(void)
{
	cpa_kernel_symbol_cache_clear();

	if (!cpa_unwind_queue_accepting())
		return;
	/* the kernel symbols every worker looks up are context 0's */
	pthread_mutex_lock(&gu_ctx_lock);
	if (kernel_symbols_ctx())
		gu_event_occur(kernel_symbols_ctx(), GU_EVENT_MODULE_RELOAD, NULL);
	pthread_mutex_unlock(&gu_ctx_lock);
}

unsigned int cpa_unwinder_pending_samples(void)
{
	return cpa_unwind_queue_pending_samples();
}

/*
 * Unwind what is still queued into the current map: the store worker before
 * a restart or its last flush.  Only while no worker holds a sample (an
 * accepted pause, or after stop): it uses the owners' contexts and buffers.
 * Otherwise the queued samples are left to the drop at cleanup.
 */
void cpa_unwinder_drain_pending(void)
{
	bool quiesced;

	pthread_mutex_lock(&restart_mutex);
	quiesced = workers_quiesced;
	pthread_mutex_unlock(&restart_mutex);
	if (!quiesced || !workers[CPA_MAIN_WORKER].ctx)
		return;

	for (unsigned int i = 0; i < worker_count; i++) {
		struct stack_sample *sample;

		while ((sample = cpa_unwind_queue_pop_sample(i)) != NULL)
			cpa_finish_unwind_sample(&workers[i], sample);
	}
}

/**
 * Worker 0, called again and again by the runtime loop of the main thread.
 */
void cpa_unwind_main_worker_fn(void *worker_ctx)
{
	(void)worker_ctx;
	pthread_mutex_lock(&restart_mutex);
	if (!workers_go) {
		workers_go = true;
		pthread_cond_broadcast(&restart_cond);
	}
	pthread_mutex_unlock(&restart_mutex);
	cpa_check_restart_loop();
	if (should_stop())
		return;
	cpa_worker_step(&workers[CPA_MAIN_WORKER]);
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
	.stop_fn = cpa_unwinder_stop,
	.destroy_fn = cpa_unwinder_destroy,
	.pause_fn = cpa_unwinder_pause,
	.restore_fn = cpa_unwinder_restore,
	.timer_fn = NULL,
	.main_worker_fn = cpa_unwind_main_worker_fn,
};
