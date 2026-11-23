// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

/*
 * Target set shared by every object that filters samples by process.
 *
 * target_ctl owns the map instance; capture objects declare the same
 * definition and adopt target_ctl's fd with bpf_map__reuse_fd() before load
 * (see target_ctl.c).  When the session does not use dynamic targets the
 * userspace loader shrinks the private copy to one entry.
 *
 * The map must stay preallocated: the on-CPU timer program is
 * BPF_PROG_TYPE_PERF_EVENT, and the 4.14 verifier only lets perf_event
 * programs use preallocated hash maps (kernel/bpf/verifier.c,
 * check_map_prog_compatibility).
 */

#ifndef CPA_TARGET_MAPS_BPF_H
#define CPA_TARGET_MAPS_BPF_H

#include "core_fixes.bpf.h"
#include <cpa_bpf/target_filter.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, TARGET_MAX_PIDS);
	__type(key, struct target_key);
	__type(value, struct target_val);
} target_pids SEC(".maps");

/* The instance identity: same value as every sample's unique_id. */
static __always_inline __u64 target_identity(struct task_struct *leader)
{
	return task_start_time_ticks(leader);
}

/* The instance key of the process @task belongs to. */
static __always_inline void target_key_of(struct task_struct *task, __u32 tgid,
					  struct target_key *key)
{
	key->tgid = tgid;
	key->pad = 0;
	key->identity = target_identity(BPF_CORE_READ(task, group_leader));
}

/* Whether the session key is present (see TARGET_SESSION_TGID). */
static __always_inline bool target_session_open(void)
{
	struct target_key key = {};

	return bpf_map_lookup_elem(&target_pids, &key) != NULL;
}

/* A TRACKED instance whose startup window, if any, has not run out. */
static __always_inline bool target_val_live(__u8 state, __u64 deadline_ns)
{
	if (state != TARGET_STATE_TRACKED)
		return false;
	return !deadline_ns || bpf_ktime_get_ns() < deadline_ns;
}

/*
 * Hot-path check: rules are never evaluated here; target_ctl selects
 * processes where they are born.  Processes that are not targets cost one
 * lookup; the session key is only consulted for targets.
 */
static __always_inline bool target_task_tracked(struct task_struct *task,
						__u32 tgid)
{
	struct target_key key;
	struct target_val *val;
	__u64 deadline_ns = 0;
	__u8 state = 0;

	target_key_of(task, tgid, &key);
	val = bpf_map_lookup_elem(&target_pids, &key);
	if (val) {
		/* copy under the NULL check for the 4.14 verifier */
		state = val->state;
		deadline_ns = val->deadline_ns;
	}
	return target_val_live(state, deadline_ns) && target_session_open();
}

#endif
