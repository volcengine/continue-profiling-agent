// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "cli_dir_manager.h"
#include "cli.h"
#include "cli_stackmap.h"
#include "cli_stackmap_private.h"
#include "cpa_runtime.h"
#include "cpa_unwinder.h"

struct cpa_worker stackmap_oneshot_worker;

const char *output_prof = NULL;
int output_fd = -1;
FILE *fp = NULL;

enum cpa_worker_init_result cpa_stackmap_oneshot_init_fn(void *cli_ctx, void *worker_ctx)
{
	if (atoi(get_arg_by_name(cli_ctx, "oneshot")) == 0)
		return CPA_INIT_SKIP;

	output_prof = get_arg_by_name(cli_ctx, "output_prof");
	fp = fopen(output_prof, "w");
	if (!fp) {
		CLI_ERROR("Open %s Failed", output_prof);
		return CPA_INIT_FAILED;
	}
	return CPA_INIT_SUCCESS;
}

void cpa_stackmap_oneshot_destroy_fn(void *worker_ctx)
{
	if (fp) {
		cpa_unwinder_drain_pending();
		struct cli_stackmap *map = cpa_main_tracemap_get_and_lock();
		cli_stackmap_to_framegraph(map, fp);
		cpa_main_tracemap_unlock();
		fclose(fp);
		fp = NULL;
		CLI_OUTPUT("prof file output to %s", output_prof);
	}
}

struct cpa_worker stackmap_oneshot_worker = {
	.worker_name = "oneshot_save",
	.worker_ctx = NULL,
	.worker_index = 5,

	.init_fn = cpa_stackmap_oneshot_init_fn,
	.destroy_fn = cpa_stackmap_oneshot_destroy_fn,
	.pause_fn = NULL,
	.restore_fn = NULL,
	.timer_fn = NULL,
	.main_worker_fn = NULL,
};
