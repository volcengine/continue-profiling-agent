// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

/*
 * target_ctl: maintains the shared target set (target_pids) that the capture
 * modules consult on every sample.
 *
 * Rules (comm / cgroup / exe) are evaluated only where a process is born:
 *   - sched_process_exec: a program image starts, the comm is final and the
 *     task already sits in the cgroup chosen by its launcher;
 *   - wake_up_new_task: a tracked process forks a child process.
 * The sampling hot paths never re-evaluate rules, they only look up the tgid.
 *
 * Linux 4.14 accepts a single BPF program per tracepoint (perf_event_set_bpf_prog
 * returns -EEXIST for a second one), so this object is the only owner of
 * sched_process_exec.  The t0 sample is taken by tail-calling a program that
 * userspace installs into t0_progs from the stack_capture object.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "core_fixes.bpf.h"
#include "target_maps.bpf.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct target_latch_val);
} target_latch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct target_rules);
} target_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} target_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} t0_progs SEC(".maps");

/*
 * Every loop below runs a compile-time constant number of iterations with no
 * break/return inside, so clang fully unrolls it: kernels before 5.3 reject
 * any back-edge.  Early exits are expressed with a result flag instead.
 */
static __always_inline bool comm_in(const char comm[TARGET_COMM_LEN],
				    const char list[TARGET_MAX_COMMS][TARGET_COMM_LEN],
				    __u8 n)
{
	const __u64 *cur = (const __u64 *)comm;
	bool hit = false;

#pragma unroll
	for (int i = 0; i < TARGET_MAX_COMMS; i++) {
		const __u64 *want = (const __u64 *)list[i];

		if (i < n && cur[0] == want[0] && cur[1] == want[1])
			hit = true;
	}
	return hit;
}

static __always_inline bool comm_in_rules(const char comm[TARGET_COMM_LEN],
					  const struct target_rules *rules)
{
	return comm_in(comm, rules->comms, rules->n_comms);
}

/* Exit capture's --exit_comm names (see target_rules::n_exit_comms). */
static __always_inline bool exit_comm_in_rules(const char comm[TARGET_COMM_LEN],
					       const struct target_rules *rules)
{
	return comm_in(comm, rules->exit_comms, rules->n_exit_comms);
}

static __always_inline bool cgroup_id_in_rules(__u64 id,
					       const struct target_rules *rules)
{
	bool hit = false;

#pragma unroll
	for (int i = 0; i < TARGET_MAX_CGROUPS; i++) {
		if (id && i < rules->n_cgroups && rules->cgroup_ids[i] == id)
			hit = true;
	}
	return hit;
}

/*
 * Walk from the task's own cgroup towards the root.  The v1 walk follows the
 * cpu controller's task_group chain so every level is read with the same
 * task_group_cgroup_id() helper that task_cgroup_id() uses; v2 follows the
 * default hierarchy's kernfs nodes like task_cgroupv2_id().
 */
static __always_inline bool task_in_rule_cgroups(struct task_struct *task,
						 const struct target_rules *rules)
{
	bool hit = false;

	if (rules->cg_hier == TARGET_CG_HIER_V1_CPU) {
		struct task_group *tg = BPF_CORE_READ(task, sched_task_group);

#pragma unroll
		for (int lvl = 0; lvl <= TARGET_CGROUP_MAX_DEPTH; lvl++) {
			if (tg && !hit) {
				if (cgroup_id_in_rules(task_group_cgroup_id(tg), rules))
					hit = true;
				else if (rules->cg_recursive)
					tg = BPF_CORE_READ(tg, parent);
				else
					tg = NULL;
			}
		}
		return hit;
	}

	struct kernfs_node *kn = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn);

#pragma unroll
	for (int lvl = 0; lvl <= TARGET_CGROUP_MAX_DEPTH; lvl++) {
		if (kn && !hit) {
			if (cgroup_id_in_rules(node_cgroup_id(kn), rules))
				hit = true;
			else if (rules->cg_recursive)
				kn = kernfs_node_parent(kn);
			else
				kn = NULL;
		}
	}
	return hit;
}

/* The executable of @task, kernel dev_t encoding; false for kernel threads. */
static __always_inline bool task_exe(struct task_struct *task, __u64 *dev,
				     __u64 *ino)
{
	struct file *exe = BPF_CORE_READ(task, mm, exe_file);

	if (!exe)
		return false;
	*ino = BPF_CORE_READ(exe, f_inode, i_ino);
	*dev = BPF_CORE_READ(exe, f_inode, i_sb, s_dev);
	return true;
}

static __always_inline bool exe_in_rules(__u64 dev, __u64 ino,
					 const struct target_rules *rules)
{
	bool hit = false;

#pragma unroll
	for (int i = 0; i < TARGET_MAX_EXES; i++) {
		if (i < rules->n_exes && rules->exe_ino[i] == ino &&
		    rules->exe_dev[i] == dev)
			hit = true;
	}
	return hit;
}

/* Rule categories are ANDed; values inside one category are ORed. */
static __always_inline bool rules_match(struct task_struct *task,
					const char comm[TARGET_COMM_LEN],
					__u64 exe_dev, __u64 exe_ino,
					const struct target_rules *rules)
{
	if (!rules->n_comms && !rules->n_cgroups && !rules->n_exes)
		return false;
	if (rules->n_comms && !comm_in_rules(comm, rules))
		return false;
	if (rules->n_cgroups && !task_in_rule_cgroups(task, rules))
		return false;
	if (rules->n_exes && !exe_in_rules(exe_dev, exe_ino, rules))
		return false;
	return true;
}

static __always_inline void emit_event(void *ctx, __u32 kind, __u32 tgid,
				       __u32 ppid, __u64 identity,
				       struct task_struct *task)
{
	struct target_event ev = {};

	ev.kind = kind;
	ev.tgid = tgid;
	ev.ppid = ppid;
	ev.identity = identity;
	ev.ts = bpf_ktime_get_ns();
	ev.cgroup_id = task_cgroup_id(task);
	BPF_CORE_READ_STR_INTO(&ev.comm, task, comm);
	bpf_perf_event_output(ctx, &target_events, BPF_F_CURRENT_CPU, &ev,
			      sizeof(ev));
}

/* First selection of an instance: start its startup window. */
static __always_inline void arm(struct target_val *val,
				const struct target_rules *rules)
{
	val->armed_ns = bpf_ktime_get_ns();
	val->deadline_ns = rules->window_ns ? val->armed_ns + rules->window_ns : 0;
}

/*
 * Insert a newly matched instance.  Under --first_match the latch is taken
 * first and committed only after the insert, so userspace never adopts a
 * winner that is rolled back here.
 */
static __always_inline bool select_new(struct target_key *key,
				       struct target_val *val,
				       const struct target_rules *rules)
{
	struct target_latch_val latch = {};
	__u32 zero = 0;

	if (!rules->first_match)
		return !bpf_map_update_elem(&target_pids, key, val, BPF_NOEXIST);

	latch.target = *key;
	if (bpf_map_update_elem(&target_latch, &zero, &latch, BPF_NOEXIST))
		return false;	/* another process won */
	if (bpf_map_update_elem(&target_pids, key, val, BPF_NOEXIST)) {
		bpf_map_delete_elem(&target_latch, &zero);
		return false;
	}
	latch.committed = 1;
	bpf_map_update_elem(&target_latch, &zero, &latch, BPF_EXIST);
	return true;
}

/*
 * A program image was just installed in current: select, re-select or
 * unselect its process.  Returns true when the process is tracked.
 */
static __always_inline bool on_exec(void *ctx)
{
	__u32 zero = 0;
	struct target_rules *rules;
	struct target_val *cur;
	struct target_val val = {};
	struct target_key key;
	struct task_struct *task;
	char comm[TARGET_COMM_LEN] = {};
	__u64 exe_dev = 0, exe_ino = 0;
	__u32 tgid, kind = 0;
	bool match, scanning, tracked = false;

	rules = bpf_map_lookup_elem(&target_rules, &zero);
	if (!rules)
		return false;

	tgid = bpf_get_current_pid_tgid() >> 32;
	task = (struct task_struct *)bpf_get_current_task();
	target_key_of(task, tgid, &key);
	bpf_get_current_comm(&comm, sizeof(comm));
	/* exit capture's names, told whatever the global selection does */
	if (exit_comm_in_rules(comm, rules))
		emit_event(ctx, TARGET_EV_EXIT_NAMED, tgid, 0, key.identity, task);
	if (!rules->enabled || !target_session_open())
		return false;
	if (rules->n_exes)
		task_exe(task, &exe_dev, &exe_ino);
	match = rules_match(task, comm, exe_dev, exe_ino, rules);

	/*
	 * Read before the lookup: userspace clears it only after its last
	 * seed insert, so a clear seen here means every seed is visible below.
	 */
	scanning = rules->scanning;
	cur = bpf_map_lookup_elem(&target_pids, &key);
	if (!cur && !match && scanning) {
		/*
		 * Fence for the initial /proc scan, which may have read this
		 * process before this exec: its seed insert (BPF_NOEXIST) now
		 * fails.  Not armed; a later matching exec selects it afresh.
		 * If the seed got in first, handle it as a known instance.
		 */
		val.state = TARGET_STATE_UNSELECTED;
		val.origin = TARGET_ORIGIN_EXEC;
		if (!bpf_map_update_elem(&target_pids, &key, &val, BPF_NOEXIST))
			return false;
		cur = bpf_map_lookup_elem(&target_pids, &key);
	}
	if (cur) {
		/*
		 * Known instance: only explicit pids and --children descendants
		 * stay selected across an exec into a program the rules do not
		 * describe.  The deadline travels with the value, so re-selection
		 * never reopens a window.  Only this exec updates the entry, and
		 * through an update, never through @cur.  (All accesses stay
		 * under this NULL check for the 4.14 verifier.)
		 */
		val = *cur;
		if (!match && val.state == TARGET_STATE_TRACKED &&
		    TARGET_ORIGIN_RULE_BOUND(val.origin)) {
			val.state = TARGET_STATE_UNSELECTED;
			kind = TARGET_EV_UNTRACKED;
		} else if (match && val.state == TARGET_STATE_UNSELECTED) {
			val.state = TARGET_STATE_TRACKED;
			if (!val.armed_ns)	/* a scan fence: first selection */
				arm(&val, rules);
			kind = TARGET_EV_TRACKED;
		}
		if (kind &&
		    bpf_map_update_elem(&target_pids, &key, &val, BPF_EXIST))
			return false;	/* entry deleted meanwhile */
		tracked = target_val_live(val.state, val.deadline_ns);
	} else if (match) {
		val.state = TARGET_STATE_TRACKED;
		val.origin = TARGET_ORIGIN_EXEC;
		arm(&val, rules);
		if (!select_new(&key, &val, rules))
			return false;
		kind = rules->first_match ? TARGET_EV_LATCHED : TARGET_EV_TRACKED;
		tracked = true;
	}

	if (kind)
		emit_event(ctx, kind, tgid, 0, key.identity, task);
	return tracked;
}

SEC("tracepoint/sched/sched_process_exec")
int target_exec(void *ctx)
{
	/* t0: sample the fresh image; a no-op when no program is installed */
	if (on_exec(ctx))
		bpf_tail_call(ctx, &t0_progs, 0);
	return 0;
}

/*
 * Stand-in when another BPF program already owns sched_process_exec (4.14
 * accepts one per tracepoint).  setup_new_exec() is exported on every
 * supported kernel and has set the new mm, exe_file and comm by the time it
 * returns.  No t0 sample: tail calls need the same program type.
 */
SEC("kretprobe/setup_new_exec")
int target_exec_kretprobe(struct pt_regs *ctx)
{
	on_exec(ctx);
	return 0;
}

SEC("kprobe/wake_up_new_task")
int BPF_KPROBE(target_fork, struct task_struct *child)
{
	__u32 zero = 0;
	struct target_rules *rules;
	struct target_val *parent;
	struct target_val val = {};
	struct target_key parent_key, child_key;
	__u32 child_pid, child_tgid;
	__u64 parent_deadline = 0;
	__u8 origin, parent_state = 0;

	rules = bpf_map_lookup_elem(&target_rules, &zero);
	if (!rules)
		return 0;

	child_pid = BPF_CORE_READ(child, pid);
	child_tgid = BPF_CORE_READ(child, tgid);
	if (child_pid != child_tgid)
		return 0;	/* new thread of an existing process */

	/*
	 * Exit capture's names: the child carries the forking thread's name
	 * until it execs, which the exit hook matches on its own.
	 */
	if (rules->n_exit_comms) {
		char comm[TARGET_COMM_LEN] = {};

		BPF_CORE_READ_STR_INTO(&comm, child, comm);
		if (exit_comm_in_rules(comm, rules))
			emit_event(ctx, TARGET_EV_EXIT_NAMED, child_tgid,
				   bpf_get_current_pid_tgid() >> 32,
				   target_identity(child), child);
	}

	if (!rules->enabled || !target_session_open())
		return 0;

	/*
	 * --children follows the process tree.  Otherwise a rule selection
	 * inherits children (same comm, cgroup and exe until they exec), except
	 * under --first_match, which selects exactly one process.
	 */
	if (rules->children)
		origin = TARGET_ORIGIN_CHILD;
	else if (!rules->first_match &&
		 (rules->n_comms || rules->n_cgroups || rules->n_exes))
		origin = TARGET_ORIGIN_INHERIT;
	else
		return 0;

	target_key_of((struct task_struct *)bpf_get_current_task(),
		      bpf_get_current_pid_tgid() >> 32, &parent_key);
	parent = bpf_map_lookup_elem(&target_pids, &parent_key);
	if (parent) {
		parent_state = parent->state;
		parent_deadline = parent->deadline_ns;
	}
	if (!target_val_live(parent_state, parent_deadline))
		return 0;

	child_key.tgid = child_tgid;
	child_key.pad = 0;
	child_key.identity = target_identity(child);
	val.state = TARGET_STATE_TRACKED;
	val.origin = origin;
	arm(&val, rules);
	if (bpf_map_update_elem(&target_pids, &child_key, &val, BPF_NOEXIST))
		return 0;
	emit_event(ctx, TARGET_EV_FORKED, child_tgid, parent_key.tgid,
		   child_key.identity, child);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
