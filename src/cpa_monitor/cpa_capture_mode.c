// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "cpa_capture_mode.h"
#include "cli.h"

#include <stdlib.h>
#include <string.h>

bool cpa_kernel_only_fastpath_requested(void *cli_ctx)
{
	const char *backend = get_arg_by_name(cli_ctx, "backend");

	if (!backend)
		return false;

	if (strncmp(backend, "bpf", strlen("bpf")) != 0)
		return false;

	if (atoi(get_arg_by_name(cli_ctx, "kernel_stack")) == 0)
		return false;

	if (atoi(get_arg_by_name(cli_ctx, "offcpu")) != 0)
		return false;

	return true;
}
