// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "cli.h"
#include "cli_cmd_helper.h"
#include "cli_common.h"

#include <linux/ptrace.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "cpa_env.h"
#include "cpa_backend_preflight.h"
#include "cpa_runtime.h"
#include "cpa_stackmap_continuous.h"
#include "cpa_unwinder.h"
#include "cpa_nobpf_unwinder_event.h"

#define WORKER_DEFINE(worker_name) extern struct cpa_worker worker_name;
#include "cpa_workers.h"
#undef WORKER_DEFINE

struct sub_cmd sub_cmd_cpa_monitor = {
	.name = "monitor",
	.arg_list =
		"store_dir=/var/log/cpa backend=bpf freq=49 record_interval=1 persistent_day=7 oneshot=0 output_prof=cpa.prof pid=0 comm=null kernel_stack=0 offcpu=0 probe=null disable_sym=0 include_full_path=0 strip_name_disable=0 record_env_name=null parse_env_values=null max_queue_size=4096 stack_size=8192 max_cache_size_mb=1024 max_store_size_mb=7168 log_print_cycles=1 bench=0 debug_option=null",
	.help_str = "[CPA] collect profile data into rotating stores or a one-shot flamegraph.",
	.func = SUB_CMD_FUNC(cpa_monitor),
};

struct cpa_worker *all_worker_list[] = {
#define WORKER_DEFINE(worker_name) &worker_name,
#include "cpa_workers.h"
#undef WORKER_DEFINE
};

int SUB_CMD_FUNC(cpa_monitor)(void *ctx)
{
	int ret = 0;

	ret = cpa_monitor_prepare_backend(ctx);
	if (ret < 0)
		return ret;

	ret = cpa_runtime_register(all_worker_list, sizeof(all_worker_list) / sizeof(struct cpa_worker *));
	if (ret < 0) {
		CLI_ERROR("Failed to register worker, errno: %d, %s", errno, strerror(errno));
		return ret;
	}

	ret = cpa_runtime_start(ctx);
	if (ret < 0) {
		CLI_ERROR("Failed to start runtime, errno: %d", ret);
		cpa_runtime_stop();
		return ret;
	}

	cpa_runtime_loop();

	ret = cpa_runtime_stop();
	if (ret)
		return ret;

	return 0;
}
