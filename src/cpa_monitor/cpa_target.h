// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CPA_TARGET_H
#define CPA_TARGET_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define CPA_TARGET_MAX_PIDS 16
#define CPA_TARGET_MAX_COMMS 8
#define CPA_TARGET_MAX_EXES 4
#define CPA_TARGET_MAX_CGROUPS 8
#define CPA_TARGET_COMM_LEN 16

/*
 * Raw process-selection arguments.  NULL, "" and "null" all mean "not set",
 * matching the monitor's default argument string.
 */
struct cpa_target_raw {
	const char *pid;
	const char *comm;
	const char *thread_comm;
	const char *exe;
	const char *cgroup;
	const char *container_pid;
	const char *startup_window;
	bool cgroup_recursive;
	bool children;
	bool new_only;
	bool first_match;
};

enum cpa_target_mode {
	/* Historical scalar filter: at most one pid and/or one thread comm. */
	CPA_TARGET_LEGACY = 0,
	/* target_ctl maintained target set. */
	CPA_TARGET_DYNAMIC = 1,
};

struct cpa_target_spec {
	enum cpa_target_mode mode;

	/* LEGACY */
	int legacy_pid;
	char legacy_thread_comm[CPA_TARGET_COMM_LEN];

	/* DYNAMIC */
	uint32_t pids[CPA_TARGET_MAX_PIDS];
	int n_pids;
	char comms[CPA_TARGET_MAX_COMMS][CPA_TARGET_COMM_LEN];
	int n_comms;
	char exes[CPA_TARGET_MAX_EXES][PATH_MAX];
	int n_exes;
	char cgroups[CPA_TARGET_MAX_CGROUPS][PATH_MAX];
	int n_cgroups;
	int container_pid;
	bool cgroup_recursive;
	bool children;
	bool new_only;
	bool first_match;
	unsigned int startup_window_sec;

	/* One-line human readable description for logs and dump metadata. */
	char summary[512];
};

/*
 * Validate and normalise the process-selection arguments.
 * Returns 0 on success; -EINVAL with a message in @err otherwise.
 */
int cpa_target_parse(const struct cpa_target_raw *raw, struct cpa_target_spec *out,
		    char *err, size_t errlen);

/* True when @spec selects by rules (comm / cgroup / exe / container). */
bool cpa_target_has_rules(const struct cpa_target_spec *spec);

/*
 * Exit capture's own selection (--exit_comm / --exit_pid) and its
 * environment condition (--exit_target_env_*).
 */
#define CPA_EXIT_MAX_ENV_NAMES 4
#define CPA_EXIT_MAX_ENV_VALUES 16
#define CPA_EXIT_ENV_NAME_LEN 64
#define CPA_EXIT_ENV_VALUE_LEN 256

struct cpa_exit_raw {
	const char *comm;
	const char *pid;
	const char *env_name;
	const char *env_values;
	const char *env_value_prefix;
};

struct cpa_exit_spec {
	char comms[CPA_TARGET_MAX_COMMS][CPA_TARGET_COMM_LEN];
	int n_comms;
	uint32_t pids[CPA_TARGET_MAX_PIDS];
	int n_pids;
	char env_names[CPA_EXIT_MAX_ENV_NAMES][CPA_EXIT_ENV_NAME_LEN];
	int n_env_names;
	char env_values[CPA_EXIT_MAX_ENV_VALUES][CPA_EXIT_ENV_VALUE_LEN];
	int n_env_values;
	char env_prefixes[CPA_EXIT_MAX_ENV_VALUES][CPA_EXIT_ENV_VALUE_LEN];
	int n_env_prefixes;
};

/* Returns 0 on success; -EINVAL with a message in @err otherwise. */
int cpa_exit_parse(const struct cpa_exit_raw *raw, struct cpa_exit_spec *out,
		   char *err, size_t errlen);

static inline bool cpa_exit_has_targets(const struct cpa_exit_spec *spec)
{
	return spec->n_comms || spec->n_pids;
}

static inline bool cpa_exit_has_env_cond(const struct cpa_exit_spec *spec)
{
	return spec->n_env_names > 0;
}

#endif
