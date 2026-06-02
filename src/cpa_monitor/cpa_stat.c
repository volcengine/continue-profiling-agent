// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "cli.h"
#include "cpa_capture_stats.h"
#include "cpa_unwinder.h"
#include "cpa_stackmap_continuous.h"
#include "cpa_nobpf_unwinder_event.h"
#include "cpa_runtime.h"
#include "cpa_bpf_capture.h"

#include <stdint.h>
#include <stdio.h>
#include <time.h>

struct cpa_stat_monitor_ctx {
	int log_print_cycles;
	int timer_cnt;
	int max_cache_size_mb;
	uint64_t bench_last_report_ns;
};

struct cpa_stat_monitor_ctx cpa_stat = {
	.log_print_cycles = 0,
	.timer_cnt = 0,
	.max_cache_size_mb = 0,
	.bench_last_report_ns = 0,
};

static const char *const bench_bucket_labels[CPA_UNWIND_BENCH_BUCKETS] = {
	"<1us", "1-4us", "4-16us", "16-64us", "64-256us", "256-512us", "512-1024us", "1024-2048us", "2048-4096us",
};

static uint64_t cpa_stat_monotonic_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;

	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void cpa_print_unwind_bench_stat(void)
{
	struct cpa_unwind_bench_stat bench_stat = { 0 };
	char hist_buf[512] = { 0 };
	size_t pos = 0;
	uint64_t now_ns;
	double rate = 0.0;
	double avg_us = 0.0;
	double min_us = 0.0;
	double max_us = 0.0;

	cpa_take_unwind_bench_stat(&bench_stat);
	if (!bench_stat.enabled)
		return;

	now_ns = cpa_stat_monotonic_ns();
	if (cpa_stat.bench_last_report_ns != 0 && now_ns > cpa_stat.bench_last_report_ns)
		rate = bench_stat.count * 1000000000.0 / (double)(now_ns - cpa_stat.bench_last_report_ns);

	cpa_stat.bench_last_report_ns = now_ns;

	if (bench_stat.count > 0) {
		avg_us = bench_stat.total_ns / (double)bench_stat.count / 1000.0;
		min_us = bench_stat.min_ns / 1000.0;
		max_us = bench_stat.max_ns / 1000.0;
	}

	CLI_OUTPUT("Bench DWARF Unwind: count=%llu rate=%.2f/s avg=%.2f us min=%.2f us max=%.2f us", (unsigned long long)bench_stat.count, rate, avg_us, min_us, max_us);

	for (unsigned int i = 0; i < CPA_UNWIND_BENCH_BUCKETS; i++) {
		int written;

		if (bench_stat.hist[i] == 0)
			continue;

		written = snprintf(hist_buf + pos, sizeof(hist_buf) - pos, "%s%s=%llu", pos ? " " : "", bench_bucket_labels[i], (unsigned long long)bench_stat.hist[i]);
		if (written < 0)
			break;
		if ((size_t)written >= sizeof(hist_buf) - pos) {
			pos = sizeof(hist_buf) - 1;
			break;
		}
		pos += (size_t)written;
	}

	if (pos > 0)
		CLI_OUTPUT("Bench DWARF Histogram: %s", hist_buf);
}

enum cpa_worker_init_result cpa_stat_monitor_init(void *cli_ctx, void *worker_ctx)
{
	cpa_stat.log_print_cycles = atoi(get_arg_by_name(cli_ctx, "log_print_cycles"));
	cpa_stat.max_cache_size_mb = atoi(get_arg_by_name(cli_ctx, "max_cache_size_mb"));
	cpa_stat.bench_last_report_ns = cpa_stat_monotonic_ns();

	if (cpa_stat.max_cache_size_mb < 100) {
		CLI_ERROR("Please use max cache size in range [100 MB, )");
		return CPA_INIT_FAILED;
	}

	// when log print cycles too long, print once after start 10s
	if (cpa_stat.log_print_cycles > 60)
		cpa_stat.timer_cnt = cpa_stat.log_print_cycles - 10;
	else
		cpa_stat.timer_cnt = 0;

	return CPA_INIT_SUCCESS;
}

void cpa_stat_monitor_destroy(void *worker_ctx)
{
}

void cpa_timer_fn(void *worker_ctx)
{
	int dir_size = 0;

	struct unwinder_stat unwind_stat;
	cpa_get_unwinder_stat(&unwind_stat);

	// gunwinder stat, need worker enabled
	struct gu_statistics *statistics = cpa_get_gunwinder_stat();

	// memory, always have
	struct rss_status rss = { 0, 0, 0 };
	get_self_rss_status(&rss);

	struct pid_tracker_stat pid_tracker_stat = { 0 };
	get_pid_tracker_stat(&pid_tracker_stat);

	struct cpa_capture_stats bpf_capture_stat = { 0 };
	struct cpa_capture_stats perf_capture_stat = { 0 };
	cpa_bpf_capture_get_stats(&bpf_capture_stat);
	cpa_perf_capture_get_stats(&perf_capture_stat);

	// map, always have
	struct cli_stackmap *map = cpa_main_tracemap_get_and_lock();
	struct cli_stackmap_memory_usage *usage = cli_stackmap_get_memory_usage(map);
	cpa_main_tracemap_unlock();

	struct dir_info *dir_info = cpa_get_stackmap_save_dir();
	if (dir_info)
		dir_size = get_directory_size(dir_info->store_dir);

	if (++cpa_stat.timer_cnt >= cpa_stat.log_print_cycles) {
		cpa_stat.timer_cnt = 0;

		CLI_OUTPUT("Parse Queue Len: %d BackTrace Time: %llu [FP] %llu [DWARF] %llu [FP_BETTER] %llu Pid Ctx: Exist: %u Alloc: %u Elf Ctx: Exist: %u Alloc: %u", unwind_stat.stack_queue_len, unwind_stat.sample_backtrace_times,
			   unwind_stat.sample_backtrace_times_fp, unwind_stat.sample_backtrace_times_dwarf, unwind_stat.sample_backtrace_times_fp_better, statistics->pid_ctx_count, statistics->pid_ctx_alloc_count, statistics->elf_ctx_count,
			   statistics->elf_ctx_alloc_count);
		CLI_OUTPUT("Detailed: Symbols Mem Size: %.2f KB | CFI FDE Size: %.2f KB | CFI Data Size %.2f KB", statistics->symbols_mem_size / 1024.0, statistics->cfi_mem_size / 1024.0, statistics->cfi_data_mem_size / 1024.0);
		CLI_OUTPUT("File  Queue Len: %d Pid Exit Queue Len: %d Store Dir: %s Total Size: %d KB", 0, 0, dir_info ? dir_info->store_dir : "NULL", dir_size / 1024);
		CLI_OUTPUT("NO BPF Pid Tracker: tracked pid num: %d retire pid num: %d", pid_tracker_stat.tracked_pid_count, pid_tracker_stat.retired_pid_count);
		CLI_OUTPUT("Lost Events: bpf perf-buffer=%llu perf mmap=%llu", (unsigned long long)bpf_capture_stat.lost_events, (unsigned long long)perf_capture_stat.lost_events);
		CLI_OUTPUT("RSS   Anon Size: %ld KB   File Size: %ld KB    Total Size: %ld KB", rss.rss_anon, rss.rss_file, rss.rss_sum);
		CLI_OUTPUT("Ids Alloc Size : %ld KB   Str Alloc Size: %ld KB Ids Array Size: %ld KB Str Array Size: %ld KB", usage->memory_usage_idsmap / 1024, usage->memory_usage_strmap / 1024, usage->memory_usage_idsarray / 1024,
			   usage->memory_usage_strarray / 1024);
		cpa_print_unwind_bench_stat();
		cpa_print_bpf_exec_time_dist();
	}

	if (usage->memory_usage_idsarray + usage->memory_usage_strarray + usage->memory_usage_idsmap + usage->memory_usage_strmap > 1024 * 1024 * cpa_stat.max_cache_size_mb) {
		cpa_runtime_need_restart();
		return;
	}

	if (dir_info && dir_size > dir_info->store_dir_max_usage * 1024 * 1024) {
		cpa_runtime_need_restart();
		return;
	}

	return;
}

struct cpa_worker cpa_stat_worker = {
	.worker_name = "cpa_stat",
	.worker_ctx = NULL,
	.worker_index = 1,

	.init_fn = cpa_stat_monitor_init,
	.destroy_fn = cpa_stat_monitor_destroy,
	.pause_fn = NULL,
	.restore_fn = NULL,
	.timer_fn = cpa_timer_fn,
	.main_worker_fn = NULL,
};
