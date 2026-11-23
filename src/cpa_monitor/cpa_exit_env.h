// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CPA_EXIT_ENV_H
#define CPA_EXIT_ENV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cpa_target.h"

/*
 * --exit_target_env_*: whether exit capture's own targets (--exit_comm /
 * --exit_pid) satisfy the environment condition, decided when a process is
 * selected; EXIT records of processes that do not are dropped.  The environ
 * is gone by the time an EXIT record is processed (exit_mm()), so it is read
 * while the process lives: at the exec or fork that gives it an --exit_comm
 * name, at the start scan, or at start for --exit_pid.
 *
 * Kept per process instance (tgid, leader start time in ticks: the samples'
 * unique_id) until the instance is reaped.  A process that exits before its
 * environ is read has no verdict (UNKNOWN); nothing waits for the read.
 */

#ifndef CPA_EXIT_ENV_MAX_ENTRIES
#define CPA_EXIT_ENV_MAX_ENTRIES 16384U
#endif

enum cpa_exit_env_verdict {
	CPA_EXIT_ENV_UNKNOWN = 0,	/* not read: gone, no environ, full */
	CPA_EXIT_ENV_MATCH,
	CPA_EXIT_ENV_MISMATCH,		/* read: no listed name set, or no match */
};

/* The condition of @spec (its env_* fields); copied. */
void cpa_exit_env_configure(const struct cpa_exit_spec *spec);
bool cpa_exit_env_enabled(void);
/* Whether @value satisfies the configured condition. */
bool cpa_exit_env_value_matches(const char *value);
/*
 * 0 with *@value the value of the first of @names (in that order) set to a
 * non-empty value in the environment of @pid, malloc'd, or NULL when none
 * is.  -1 when there is no environment to read (the process is gone, past
 * exit_mm(), or inside exec before the loader set it up).
 */
int cpa_exit_env_lookup(uint32_t pid, char *const *names, int n_names, char **value);
/* The thread that reads the processes cpa_exit_env_selected() names. */
int cpa_exit_env_start(void);
void cpa_exit_env_stop(void);
/* An exec or fork selected (@tgid, @identity): read it soon, off this thread. */
void cpa_exit_env_selected(uint32_t tgid, uint64_t identity);
/* Read (@tgid, @identity) now; false when there is no environ to read. */
bool cpa_exit_env_read(uint32_t tgid, uint64_t identity);
/* The verdict for the EXIT record of (@tgid, @identity). */
enum cpa_exit_env_verdict cpa_exit_env_verdict(uint32_t tgid, uint64_t identity);
void cpa_exit_env_on_pid_exit(uint32_t tgid, uint64_t identity);
unsigned int cpa_exit_env_count(void);

#endif
