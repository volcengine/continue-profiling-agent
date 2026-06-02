// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "cpa_stackmap_continuous.h"
#include "cli.h"
#include "cli_config.h"
#include "cpa_unwinder.h"
#include <sys/sysinfo.h>

#define CPA_TIMEWHEEL_HOLD_MS 10000ULL

struct stackmap_store_info {
	const char *store_dir;
	int max_store_size_mb;
	int persistent_day;
	struct dir_info *store_dir_info;
	struct dir_info *pending_dir_info;
	void *cli_ctx;
};

struct stackmap_store_info store_info = { 0 };

struct dir_info *cpa_get_stackmap_save_dir(void)
{
	return store_info.store_dir_info;
}

static bool cpa_stackmap_continuous_enabled(void)
{
	return store_info.store_dir_info != NULL;
}

static void cpa_free_dir_info(struct dir_info *dir_info)
{
	if (!dir_info)
		return;

	free(dir_info->store_dir);
	free(dir_info);
}

static void save_monitor_config(void *ctx)
{
	if (!store_info.store_dir_info)
		return;

	char *path = path_join(store_info.store_dir_info->store_dir, "conf");
	if (!path)
		return;

	struct cli_config *config = cli_config_init(path);
	if (!config) {
		free(path);
		return;
	}

	free(path);

	char cpu_num[8];
	int nprocs = get_nprocs();

	snprintf(cpu_num, 8, "%d", nprocs);

	add_config_item(config, "version", CLI_VERSION);
	add_config_item(config, "cpu_num", cpu_num);

#define ADD_CONFIG(name) add_config_item(config, #name, get_arg_by_name(ctx, #name))

	ADD_CONFIG(freq);
	ADD_CONFIG(record_interval);
	ADD_CONFIG(persistent_day);
	ADD_CONFIG(record_env_name);
	ADD_CONFIG(kernel_stack);
	ADD_CONFIG(stack_size);

	CLI_OUTPUT("write config to %s", config->config_path);

	dump_config(config);
	cli_config_destroy(config);

	return;
}

static int cpa_new_dir(void)
{
	struct dir_info *old_dir_info = store_info.store_dir_info;
	struct dir_info *new_dir_info = get_single_store_dir_name(store_info.store_dir, "cpa", store_info.max_store_size_mb, store_info.persistent_day);

	if (!new_dir_info) {
		CLI_ERROR("Failed to rotate store directory, keeping previous directory");
		return -1;
	}

	store_info.store_dir_info = new_dir_info;

	if (old_dir_info) {
		if (old_dir_info->store_dir)
			free(old_dir_info->store_dir);
		free(old_dir_info);
	}

	return 0;
}

static int cpa_stage_new_dir(void)
{
	cpa_stackmap_continuous_abort_restart();

	store_info.pending_dir_info = get_single_store_dir_name(store_info.store_dir, "cpa", store_info.max_store_size_mb, store_info.persistent_day);
	if (!store_info.pending_dir_info) {
		CLI_ERROR("Failed to stage store directory rotation");
		return -1;
	}

	return 0;
}

static int cpa_enable_stackmap_timewheel(void)
{
	struct cli_stackmap *maps = cpa_main_tracemap_get_and_lock();
	int ret = cli_stackmap_enable_timewheel(maps, CPA_TIMEWHEEL_HOLD_MS);

	cpa_main_tracemap_unlock();
	return ret;
}

enum cpa_worker_init_result cpa_stackmap_continous_init_fn(void *cli_ctx, void *worker_ctx)
{
	if (atoi(get_arg_by_name(cli_ctx, "oneshot")) == 1)
		return CPA_INIT_SKIP;

	store_info.store_dir = get_arg_by_name(cli_ctx, "store_dir");
	store_info.max_store_size_mb = atoi(get_arg_by_name(cli_ctx, "max_store_size_mb"));
	store_info.persistent_day = atoi(get_arg_by_name(cli_ctx, "persistent_day"));
	store_info.cli_ctx = cli_ctx;

	if (store_info.max_store_size_mb < 1024) {
		CLI_ERROR("Please use max store dir usage size in range [1024 MB, )");
		return CPA_INIT_FAILED;
	}

	if (access(store_info.store_dir, F_OK) == -1) {
		CLI_ERROR("Store Dir Not exists %s", store_info.store_dir);
		return CPA_INIT_FAILED;
	}

	if (cpa_new_dir() < 0)
		return CPA_INIT_FAILED;
	save_monitor_config(store_info.cli_ctx);
	if (cpa_enable_stackmap_timewheel() != 0) {
		CLI_ERROR("Failed to enable CPA stackmap timewheel");
		cpa_free_dir_info(store_info.store_dir_info);
		store_info.store_dir_info = NULL;
		return CPA_INIT_FAILED;
	}

	return CPA_INIT_SUCCESS;
}

static void cpa_stackmap_continuous_flush_current(bool flush_all)
{
	struct cli_stackmap *maps = NULL;

	if (!cpa_stackmap_continuous_enabled())
		return;

	maps = cpa_main_tracemap_get_and_lock();
	if (maps) {
		uint64_t now_record_ms = cli_stackmap_now_record_ms(maps);

		if (flush_all) {
			cli_stackmap_dump_delta_stack_flush_all(maps, store_info.store_dir_info->store_dir, now_record_ms);
		} else {
			cli_stackmap_dump_delta_stack_at(maps, store_info.store_dir_info->store_dir, now_record_ms);
		}
	}
	cpa_main_tracemap_unlock();
}

int cpa_stackmap_continuous_prepare_restart(void)
{
	if (!cpa_stackmap_continuous_enabled())
		return 0;

	/*
	 * Restart is staged. Drain pending unwind work into the current map,
	 * flush all complete buckets, then create a pending directory that is
	 * committed only after the runtime has allocated a replacement tracemap.
	 */
	cpa_unwinder_drain_pending();
	cpa_stackmap_continuous_flush_current(true);
	return cpa_stage_new_dir();
}

int cpa_stackmap_continuous_commit_restart(void)
{
	struct dir_info *old_dir_info = NULL;

	if (!store_info.pending_dir_info) {
		CLI_ERROR("Failed to commit restart store directory: no staged directory");
		return -1;
	}

	old_dir_info = store_info.store_dir_info;
	store_info.store_dir_info = store_info.pending_dir_info;
	store_info.pending_dir_info = NULL;
	/* The old directory remains on disk; only the in-memory pointer moves. */
	cpa_free_dir_info(old_dir_info);
	save_monitor_config(store_info.cli_ctx);
	return 0;
}

static void cpa_stackmap_continous_restore_fn(void *worker_ctx)
{
	(void)worker_ctx;
	if (cpa_stackmap_continuous_enabled() && cpa_enable_stackmap_timewheel() != 0)
		CLI_ERROR("Failed to restore CPA stackmap timewheel");
}

void cpa_stackmap_continuous_abort_restart(void)
{
	if (!store_info.pending_dir_info)
		return;

	remove_directory(store_info.pending_dir_info->store_dir);
	cpa_free_dir_info(store_info.pending_dir_info);
	store_info.pending_dir_info = NULL;
}

void cpa_stackmap_continous_timer_fn(void *worker_ctx)
{
	cpa_stackmap_continuous_flush_current(false);
}

static void cpa_stackmap_continous_destroy_fn(void *worker_ctx)
{
	cpa_unwinder_drain_pending();
	cpa_stackmap_continuous_flush_current(true);
	cpa_stackmap_continuous_abort_restart();
	cpa_free_dir_info(store_info.store_dir_info);
	store_info.store_dir_info = NULL;
}

struct cpa_worker stackmap_continous_worker = {
	.worker_name = "continous_save",
	.worker_ctx = NULL,
	.worker_index = 5,

	.init_fn = cpa_stackmap_continous_init_fn,
	.destroy_fn = cpa_stackmap_continous_destroy_fn,
	.pause_fn = NULL,
	.restore_fn = cpa_stackmap_continous_restore_fn,
	.timer_fn = cpa_stackmap_continous_timer_fn,
	.main_worker_fn = NULL,
};
