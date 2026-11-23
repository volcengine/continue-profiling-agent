// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

/*
 * Shared contract between the target_ctl BPF module, the capture modules that
 * consult the target set (stack_capture, offcpu_capture) and the userspace
 * controller (src/cpa_monitor/cpa_target_ctl.c).
 *
 * The target set is a hash keyed by process instance.  Selection rules (comm, cgroup, exe)
 * are only evaluated where a process is born (exec/fork in BPF, the initial
 * /proc scan in userspace); sampling hot paths only look the process up.
 */

#ifndef CPA_BPF_TARGET_FILTER_H
#define CPA_BPF_TARGET_FILTER_H

#ifndef __BPF__
#include <linux/types.h>
#endif

#define TARGET_MAX_PIDS 40960
#define TARGET_MAX_COMMS 8
#define TARGET_MAX_CGROUPS 8
#define TARGET_MAX_EXES 4
#define TARGET_COMM_LEN 16
/* Levels walked above a task's own cgroup for recursive matching. */
#define TARGET_CGROUP_MAX_DEPTH 8

/*
 * A target is a process *instance*: tgid plus the group leader's start time
 * in USER_HZ ticks on the boot-time clock -- exactly field 22 of
 * /proc/<pid>/stat, so BPF and userspace compare values from one time domain.
 * The instance is the map key, so an entry left by an earlier process can
 * never be confused with, or removed instead of, a later one that reuses the
 * pid.
 *
 * Who writes what.  Only map inserts, updates and deletes are used, never a
 * store through a looked-up pointer (updating a preallocated hash recycles
 * the old element at once), and every entry has a single updater:
 *   - BPF inserts entries (exec, fork) and moves an instance between TRACKED
 *     and UNSELECTED at its own exec; it never deletes;
 *   - userspace inserts the initial seeds (BPF_NOEXIST), deletes an instance
 *     once it has no live thread, and owns the session key; it never updates
 *     an entry.
 *
 *   TRACKED ----exec, rules no longer match----> UNSELECTED
 *   UNSELECTED --exec, rules match again-------> TRACKED
 *
 * The startup window is a deadline fixed when the instance is first armed
 * and carried along by every update, so no transition can reopen it; the
 * sampling gate enforces it.
 */
struct target_key {
	__u32 tgid;
	__u32 pad;
	__u64 identity;		/* leader boot-time start, USER_HZ ticks */
};

/*
 * The all-zero key (tgid 0 is the idle task, never a target) marks an open
 * session.  Every gate requires it, so deleting it stops sampling of all
 * targets -- known to userspace or not -- and all new selections at once.
 */
#define TARGET_SESSION_TGID 0

enum target_state {
	TARGET_STATE_TRACKED = 2,
	TARGET_STATE_UNSELECTED = 4,
};

enum target_origin {
	TARGET_ORIGIN_STATIC = 1,	/* explicit --pid list */
	TARGET_ORIGIN_SCAN = 2,		/* rule match found in /proc */
	TARGET_ORIGIN_EXEC = 3,		/* rule match at exec */
	TARGET_ORIGIN_INHERIT = 4,	/* forked by a rule match; re-checked at exec */
	TARGET_ORIGIN_CHILD = 5,	/* --children: follows the process tree */
};

/* Selections that exist only because the current program image matches. */
#define TARGET_ORIGIN_RULE_BOUND(origin) \
	((origin) == TARGET_ORIGIN_SCAN || (origin) == TARGET_ORIGIN_EXEC || \
	 (origin) == TARGET_ORIGIN_INHERIT)

enum target_cgroup_hier {
	TARGET_CG_HIER_V1_CPU = 0,	/* pairs with task_cgroup_id()/cgroup_cpu_id() */
	TARGET_CG_HIER_V2_DFL = 1,	/* pairs with task_cgroupv2_id() */
};

struct target_val {
	__u64 armed_ns;		/* CLOCK_MONOTONIC when first selected, 0 = never */
	__u64 deadline_ns;	/* armed_ns + startup window, 0 = no window */
	__u8 state;
	__u8 origin;
	__u8 pad[6];
};

/*
 * --first_match winner.  Taken before the target entry is inserted and
 * committed after it, so a reader never adopts a winner that is rolled back.
 */
struct target_latch_val {
	struct target_key target;
	__u8 committed;
	__u8 pad[7];
};

struct target_rules {
	__u8 enabled;
	__u8 first_match;
	__u8 new_only;
	__u8 children;
	__u8 cg_recursive;
	__u8 cg_hier;
	__u8 n_comms;
	__u8 n_cgroups;
	__u8 n_exes;
	/*
	 * The initial /proc scan is running: an exec of an unknown process
	 * that does not match leaves an UNSELECTED fence, so a seed read
	 * before that exec can no longer be inserted.
	 */
	__u8 scanning;
	/*
	 * Exit capture's --exit_comm, when --exit_target_env_name wants the
	 * environment of those processes: an exec into one of these names, or
	 * a fork by a process of one, is told (TARGET_EV_EXIT_NAMED) so that
	 * userspace reads the environ while the process lives.  Independent of
	 * @enabled; nothing is written to a map.
	 */
	__u8 n_exit_comms;
	__u8 pad[5];
	__u64 window_ns;	/* --startup_window, 0 = none */
	/* NUL padded so two u64 compares decide an exact comm match. */
	char comms[TARGET_MAX_COMMS][TARGET_COMM_LEN];
	__u64 cgroup_ids[TARGET_MAX_CGROUPS];
	__u64 exe_dev[TARGET_MAX_EXES];	/* kernel dev_t encoding (major << 20 | minor) */
	__u64 exe_ino[TARGET_MAX_EXES];
	char exit_comms[TARGET_MAX_COMMS][TARGET_COMM_LEN];
};

/*
 * Notifications only wake the userspace controller; it re-reads the maps,
 * which are the source of truth, so a lost or late event cannot corrupt state.
 */
enum target_event_kind {
	TARGET_EV_TRACKED = 1,
	TARGET_EV_LATCHED = 2,
	TARGET_EV_FORKED = 3,
	TARGET_EV_UNTRACKED = 4,
	TARGET_EV_EXIT_NAMED = 5,	/* see target_rules::n_exit_comms */
};

struct target_event {
	__u32 kind;
	__u32 tgid;
	__u32 ppid;
	__u32 pad;
	__u64 identity;
	__u64 ts;
	__u64 cgroup_id;
	char comm[TARGET_COMM_LEN];
};

#endif
