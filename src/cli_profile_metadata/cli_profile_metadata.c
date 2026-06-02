// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "cli_profile_metadata.h"

#define MAX_FIELDS 3

char cpa_base_info[CPA_BASE_INFO_LEN];

static void split_comm(const char *merged, char *comm, char *group_comm)
{
	/* comm and group_comm are fixed 15-byte, space-padded fields. */
	int comm_end = 14;
	while (comm_end >= 0 && merged[comm_end] == ' ') {
		comm_end--;
	}

	int group_comm_end = 29;
	while (group_comm_end >= 15 && merged[group_comm_end] == ' ') {
		group_comm_end--;
	}

	if (comm_end >= 0) {
		strncpy(comm, merged, comm_end + 1);
		comm[comm_end + 1] = '\0';
	} else {
		comm[0] = '\0';
	}

	if (group_comm_end >= 15) {
		strncpy(group_comm, merged + 15, group_comm_end - 14);
		group_comm[group_comm_end - 14] = '\0';
	} else {
		group_comm[0] = '\0';
	}
}

static char *merge_comm(const char *comm, const char *group_comm)
{
	char merged[31];
	size_t comm_len;

	/* Keep the on-disk label prefix byte-compatible with parse_metadata(). */
	memset(merged, ' ', 30);
	merged[30] = '\0';

	comm_len = strnlen(comm, 15);
	memcpy(merged, comm, comm_len);

	comm_len = strnlen(group_comm, 15);
	memcpy(merged + 15, group_comm, comm_len);

	return strdup(merged);
}

int generate_metadata(char *output, int max_size, char *comm, char *group_comm, int cg_id, int cpu, int pid, char *env_name)
{
	char *merged = merge_comm(comm, group_comm);

	snprintf(output, max_size, "%s-%d-%d-%d|%s", merged, cg_id, cpu, pid, env_name);
	free(merged);

	return 0;
}

int parse_metadata(const char *input, struct metadata *data)
{
	const char *delim = "-";
	const char *pos = input;
	const char *last_delim[MAX_FIELDS] = { NULL };
	int i, field_count = 0;

	data->raw = input;

	strncpy(cpa_base_info, input, CPA_BASE_INFO_LEN - 1);
	cpa_base_info[CPA_BASE_INFO_LEN - 1] = '\0';

	char *env_name = strchr(cpa_base_info, '|');
	if (env_name) {
		*env_name = '\0';
		env_name++;
	} else {
		return -1;
	}

	strncpy(data->env, env_name, CPA_ENV_LEN - 1);
	data->env[CPA_ENV_LEN - 1] = '\0';

	size_t base_len = strnlen(cpa_base_info, CPA_BASE_INFO_LEN);
	if (base_len == 0)
		return -1;

	/*
	 * Split numeric suffixes from the tail. The fixed-width comm prefix is
	 * not tokenized, so embedded punctuation cannot disturb numeric parsing.
	 */
	for (pos = cpa_base_info + base_len - 1; pos >= cpa_base_info; pos--) {
		if (*pos == '-') {
			last_delim[field_count++] = pos;
			if (field_count == MAX_FIELDS)
				break;
		}
	}

	if (field_count != MAX_FIELDS)
		return -1;

	char merged[TASK_COMM_LEN * 2 - 1];
	memcpy(merged, cpa_base_info, TASK_COMM_LEN * 2 - 2);
	merged[TASK_COMM_LEN * 2 - 2] = '\0';

	split_comm(merged, data->comm, data->group_comm);

	data->comm[TASK_COMM_LEN - 1] = '\0';
	data->group_comm[TASK_COMM_LEN - 1] = '\0';

	data->cg_id = strtoul(last_delim[2] + 1, NULL, 10);
	data->cpu = atoi(last_delim[1] + 1);
	data->pid = atoi(last_delim[0] + 1);

	return 0;
}
