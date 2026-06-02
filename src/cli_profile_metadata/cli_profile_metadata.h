// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CLI_PROFILE_METADATA_H
#define CLI_PROFILE_METADATA_H

#include "cli.h"
#include <stdio.h>
#include <stdlib.h>

/**
 * @file cli_profile_metadata.h
 * @brief Metadata serialization helpers for folded-stack records.
 */

/**
 * struct metadata - decoded folded-stack metadata header
 * @comm: thread comm
 * @group_comm: process/group comm
 * @env: selected environment tag
 * @cg_id: cgroup id
 * @cpu: cpu id
 * @pid: task pid
 * @raw: pointer to the original serialized metadata blob
 */
struct metadata {
	char comm[TASK_COMM_LEN];
	char group_comm[TASK_COMM_LEN];
	char env[CPA_ENV_LEN + 1];
	unsigned long cg_id;
	int cpu;
	unsigned int pid;
	const char *raw;
};

/**
 * generate_metadata - serialize metadata into caller-provided buffer.
 * @output: output destination.
 * @max_size: output buffer length.
 * @comm: thread comm value.
 * @group_comm: group comm value.
 * @cg_id: cgroup id.
 * @cpu: cpu id.
 * @pid: process id.
 * @env_name: environment suffix.
 * @return: 0 on success, negative on failure.
 */
int generate_metadata(char *output, int max_size, char *comm, char *group_comm, int cg_id, int cpu, int pid, char *env_name);

/**
 * parse_metadata - parse metadata prefix from serialized record.
 * @input: serialized metadata string.
 * @data: decoded output.
 * @return: 0 on success, negative on failure.
 */
int parse_metadata(const char *input, struct metadata *data);

/**
 * @cpa_base_info - process-local base info cache used by CLI metadata output.
 */
extern char cpa_base_info[CPA_BASE_INFO_LEN];

#endif /* CLI_PROFILE_METADATA_H */
