// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "cli.h"
#include "cli_cmd_helper.h"
#include "cli_output.h"

#include <errno.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/utsname.h>

#include <cpa_bpf/capabilities.h>

int SUB_CMD_FUNC(cpa_capabilities)(void *ctx);

struct sub_cmd sub_cmd_cpa_capabilities = {
	.name = "capabilities",
	.arg_list = NULL,
	.help_str = "[CPA] show what this kernel lets cpa monitor do, as key-value lines.",
	.func = SUB_CMD_FUNC(cpa_capabilities),
};

/*
 * One "key: value" per line, keys stable across releases: schema_version
 * changes when a key changes meaning.  Needs the same privileges as
 * `cpa monitor`; without them every capability reads permission_denied.
 */
int SUB_CMD_FUNC(cpa_capabilities)(void *ctx)
{
	const struct cpa_capability_set *caps;
	struct utsname kernel;
	int id;

	(void)ctx;
	/* probe under the memlock limit cpa monitor runs with (kernels before 5.11 charge it) */
	setrlimit(RLIMIT_MEMLOCK, &(struct rlimit){ RLIM_INFINITY, RLIM_INFINITY });
	if (uname(&kernel) < 0) {
		CLI_ERROR("cannot read the kernel release: errno=%d", errno);
		return -errno;
	}
	caps = cpa_capabilities_get();
	if (!caps) {
		CLI_ERROR("cannot probe the kernel capabilities");
		return -EIO;
	}

	printf("schema_version: 1\n");
	printf("kernel.sysname: %s\n", kernel.sysname);
	printf("kernel.release: %s\n", kernel.release);
	printf("kernel.machine: %s\n", kernel.machine);
	for (id = 0; id < CPA_CAP_COUNT; id++) {
		const struct cpa_capability_result *r = cpa_capabilities_result(caps, (enum cpa_capability_id)id);
		const char *name = cpa_capability_id_name((enum cpa_capability_id)id);

		printf("capability.%s.state: %s\n", name, cpa_capability_state_name(r->state));
		printf("capability.%s.reason: %s\n", name, cpa_capability_reason_name(r->reason));
		printf("capability.%s.error_code: %d\n", name, r->error_code);
	}
	return ferror(stdout) ? -EIO : 0;
}
