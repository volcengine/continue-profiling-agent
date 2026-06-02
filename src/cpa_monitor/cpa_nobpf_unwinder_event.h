// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CPA_NOBPF_UNWINDER_EVENT_H
#define CPA_NOBPF_UNWINDER_EVENT_H

#include "cpa_runtime.h"

/**
 * @file cpa_nobpf_unwinder_event.h
 * @brief PID tracker for no-BPF unwind mode.
 */

/**
 * struct pid_tracker_stat - pid tracker counters used by diagnostics
 * @retired_pid_count: number of stale pid entries retired from the tracker
 * @tracked_pid_count: number of pid entries currently kept in the tracker
 */
struct pid_tracker_stat {
	uint64_t retired_pid_count;
	uint64_t tracked_pid_count;
};

/**
 * get_pid_comm_auto_retire - fetch comm and opportunistically retire stale pids
 * @pid: target pid
 * @comm: destination buffer of at least TASK_COMM_LEN bytes
 *
 * The tracker uses a hash table for O(1) comm lookup and a min-heap to bound
 * stale-entry cleanup work under backpressure.
 *
 * Return: 0 on success, negative value on failure.
 */
int get_pid_comm_auto_retire(int pid, char *comm);

/**
 * get_pid_comm_direct - fetch process comm without retire-side effects
 * @pid: target pid
 * @comm: destination buffer of at least TASK_COMM_LEN bytes
 *
 * Return: 0 on success, negative value on failure.
 */
int get_pid_comm_direct(int pid, char *comm);

/**
 * get_pid_tracker_stat - snapshot pid tracker counters
 * @stat: destination for the current tracker statistics
 */
void get_pid_tracker_stat(struct pid_tracker_stat *stat);

#endif /* CPA_NOBPF_UNWINDER_EVENT_H */
