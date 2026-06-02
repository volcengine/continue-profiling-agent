// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "cpa_debug.h"

#include <cli.h>
#include <string.h>
#include "cpa_runtime.h"

struct debug_options {
	int pid;
	int samples_per_dump;
	char *debug_dump_path;
	int dump_count;
	bool dump_related;
	bool enabled;
};

struct debug_options debug_opt = { .enabled = false, .dump_related = false, .pid = 0 };

void cpa_debug_dump_destroy(void *worker_ctx)
{
	if (debug_opt.debug_dump_path) {
		free(debug_opt.debug_dump_path);
		debug_opt.debug_dump_path = NULL;
	}
}

enum cpa_worker_init_result cpa_debug_dump_init(void *cli_ctx, void *worker_ctx)
{
	const char *debug_option = get_arg_by_name(cli_ctx, "debug_option");
	if (cli_arg_is_null_default(debug_option)) {
		debug_opt.enabled = false;
		return CPA_INIT_SKIP;
	}

	int size = 0;
	char **debug_opt_list = get_single_list_args(debug_option, &size);

	if (size != 3)
		goto format_error;

	debug_opt.pid = atoi(debug_opt_list[0]);
	debug_opt.samples_per_dump = atoi(debug_opt_list[1]);
	debug_opt.debug_dump_path = strdup(debug_opt_list[2]);
	debug_opt.dump_related = 1;

	free_single_list_args(debug_opt_list, size);
	debug_opt_list = NULL;

	if (debug_opt.pid < 1 || debug_opt.samples_per_dump < 1) {
		CLI_ERROR("pid or samples_per_dump is invalid, pid %d samples %d", debug_opt.pid, debug_opt.samples_per_dump);
		goto format_error;
	}

	struct stat path_stat;
	if (stat(debug_opt.debug_dump_path, &path_stat) != 0) {
		CLI_ERROR("dump file path not exists %s", debug_opt.debug_dump_path);
		goto format_error;
	}

	if (!S_ISDIR(path_stat.st_mode)) {
		CLI_ERROR("dump file path not dir %s", debug_opt.debug_dump_path);
		goto format_error;
	}

	CLI_OUTPUT("Enable Debug Dump, pid %d samples %d dump_path %s", debug_opt.pid, debug_opt.samples_per_dump, debug_opt.debug_dump_path);

	debug_opt.enabled = true;

	return CPA_INIT_SUCCESS;

format_error:
	CLI_ERROR("format error, use {pid > 1},{samples_per_dump > 1},{debug_dump_path(must exists dir)}. option is %s", debug_option);

	if (debug_opt_list)
		free_single_list_args(debug_opt_list, size);

	return CPA_INIT_FAILED;
}

static inline bool should_debug_dump_sample(int pid)
{
	if (!debug_opt.enabled || pid != debug_opt.pid)
		return false;
	if (debug_opt.dump_count++ % debug_opt.samples_per_dump == 0)
		return true;
	return false;
}

void cpa_debug_dump_sample(struct stack_sample *sample)
{
	if (should_debug_dump_sample(sample->pid)) {
		gu_debug_dump_sample(sample->info, debug_opt.debug_dump_path, debug_opt.dump_related);
		if (debug_opt.dump_related)
			debug_opt.dump_related = 0;
	}
}

struct cpa_worker debug_dump_worker = {
	.worker_name = "debug_dump_worker",
	.worker_ctx = NULL,
	.worker_index = CPA_WORKER_INDEX_NOCARE,

	.init_fn = cpa_debug_dump_init,
	.destroy_fn = cpa_debug_dump_destroy,
	.pause_fn = NULL,
	.restore_fn = NULL,
	.timer_fn = NULL,
	.main_worker_fn = NULL,
};
