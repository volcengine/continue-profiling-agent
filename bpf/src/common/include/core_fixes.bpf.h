/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Hengqi Chen */
/* Copyright (c) 2024 ByteDance */

/**
 * @file core_fixes.bpf.h
 * @brief CO-RE helpers and shims for kernel-layout differences.
 */

#ifndef CPA_BPF_CORE_FIXES_BPF_H
#define CPA_BPF_CORE_FIXES_BPF_H

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>

#define PERF_MAX_STACK_DEPTH 127

/* macros used to define map size */
#define CGROUP_MAX_ENTRIES 4096
#define TASK_MAX_ENTRIES 40960
#define STACK_MAX_ENTRIES 4096

#define BIO_MAX_ENTRIES 40960
#define RQ_MAX_ENTRIES 40960

#ifdef DEBUG
#define LOG(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define LOG(fmt, ...)
#endif

#define BUG(fmt, ...) bpf_printk("[bug] " fmt, ##__VA_ARGS__)

/**
 * commit 2f064a59a1 ("sched: Change task_struct::state") changes
 * the name of task_struct::state to task_struct::__state
 * see:
 *     https://github.com/torvalds/linux/commit/2f064a59a1
 */
struct task_struct___x {
	unsigned int __state;
};

/**
 * Read task state across kernel versions where field name changed.
 */
static __always_inline __s64 get_task_state(struct task_struct *task)
{
	struct task_struct___x *t = (struct task_struct___x *)task;

	if (bpf_core_field_exists(t->__state))
		return BPF_CORE_READ(t, __state);
	return BPF_CORE_READ(task, state);
}

struct kernfs_node___old {
	union {
		struct {
			u32 ino;
			u32 generation;
		};
		u64 id;
	} id;
};

/*
 * commit 67c0496e87d1 ("kernfs: convert kernfs_node->id from union 
 * kernfs_node_id to u64") changes the type of kernfs_node::id from
 * union kernfs_node_id to u64.
 */
struct kernfs_node___new {
	u64 id;
};

/**
 * Resolve cgroup identifier regardless of kernfs structure layout.
 */
static __always_inline u64 node_cgroup_id(struct kernfs_node *node)
{
	if (bpf_core_type_exists(union kernfs_node_id) == 1) {
		struct kernfs_node___old *n = (struct kernfs_node___old *)node;
		return BPF_CORE_READ(n, id.id);
	} else {
		struct kernfs_node___new *n = (struct kernfs_node___new *)node;
		return BPF_CORE_READ(n, id);
	}
}

static __always_inline u64 task_group_cgroup_id(struct task_group *tg)
{
	struct kernfs_node *node;

	node = BPF_CORE_READ(tg, css.cgroup, kn);
	return node_cgroup_id(node);
}

static __always_inline u64 memcg_cgroup_id(struct mem_cgroup *memcg)
{
	struct kernfs_node *node;

	node = BPF_CORE_READ(memcg, css.cgroup, kn);
	return node_cgroup_id(node);
}

static __always_inline u64 wbc_cgroup_id(struct writeback_control *wbc)
{
	struct kernfs_node *node;
	struct bdi_writeback *wb;

	wb = BPF_CORE_READ(wbc, wb);
	if (wb == 0)
		return 0;

	node = BPF_CORE_READ(wb, memcg_css, cgroup, kn);

	return node_cgroup_id(node);
}

static __always_inline u64 css_set_cgroup_id(struct css_set *cs)
{
	struct kernfs_node *node;

	node = BPF_CORE_READ(cs, dfl_cgrp, kn);
	return node_cgroup_id(node);
}

static __always_inline u64 task_cgroupv2_id(struct task_struct *task)
{
	struct css_set *cs;

	cs = BPF_CORE_READ(task, cgroups);
	return css_set_cgroup_id(cs);
}

static __always_inline u64 task_cgroup_id(struct task_struct *task)
{
	struct task_group *tg;
	u64 id;

	if (BPF_CORE_READ(task, pid) == 0)
		return 0;

	tg = BPF_CORE_READ(task, sched_task_group);

	id = task_group_cgroup_id(tg);
	if (id != 0)
		return id;

	return task_cgroupv2_id(task);
}

static __always_inline u64 task_memcg_cgroup_id(struct task_struct *task)
{
	struct mem_cgroup *memcg;

	if (BPF_CORE_READ(task, pid) == 0)
		return 0;

	if (bpf_core_field_exists(task->active_memcg))
		memcg = BPF_CORE_READ(task, active_memcg);
	else
		return 0;

	return memcg_cgroup_id(memcg);
}

/**
 * Resolve current task cgroup id.
 */
static __always_inline u64 current_task_cid(void)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	return task_cgroup_id(task);
}

#ifndef BPF_CORE_CONTAINER_OF
#define BPF_CORE_CONTAINER_OF(ptr, type, member)                                                                                                                                                                                                               \
	({                                                                                                                                                                                                                                                     \
		void *__mptr = (void *)(ptr);                                                                                                                                                                                                                  \
		((type *)(__mptr - bpf_core_field_offset(type, member)));                                                                                                                                                                                      \
	})
#endif

static __always_inline u64 cfs_rq_cgroup_id(struct cfs_rq *cfs_rq)
{
	struct task_group *tg;

	tg = BPF_CORE_READ(cfs_rq, tg);
	return task_group_cgroup_id(tg);
}

static __always_inline u64 cfs_b_cgroup_id(struct cfs_bandwidth *cfs_b)
{
	struct task_group *tg;

	tg = BPF_CORE_CONTAINER_OF(cfs_b, struct task_group, cfs_bandwidth);
	return task_group_cgroup_id(tg);
}

static __always_inline u64 bio_cgroup_id(struct bio *bio)
{
	struct blkcg_gq *bi_blkg;
	struct kernfs_node *node;

	bi_blkg = BPF_CORE_READ(bio, bi_blkg);
	if (!bi_blkg)
		return 0;

	node = BPF_CORE_READ(bi_blkg, blkcg, css.cgroup, kn);
	return node_cgroup_id(node);
}

static __always_inline unsigned long get_percpu_addr(unsigned long per_cpu_offset_addr, int cpu, unsigned long off)
{
	int ret = 0;
	unsigned long percpu_base = 0;

	ret = bpf_probe_read_kernel(&percpu_base, sizeof(unsigned long), (const void *)(per_cpu_offset_addr + cpu * sizeof(unsigned long)));
	if (ret != 0)
		return 0;

	return percpu_base + off;
}

#if defined(bpf_target_x86)
#define user_mode(regs) (!!((regs).cs & 3))
#elif defined(bpf_target_arm64)
#define user_mode(regs) (((regs).pstate & 0xf) == 0)
#else
#error "Unsupported architecture"
#endif

#define BPF_F_USER_STACK (1ULL << 8)
#define BPF_F_FAST_STACK_CMP (1ULL << 9)
#define BPF_F_REUSE_STACKID (1ULL << 10)

/*
 * Lower 16bit is the offset against the beginning of the event entry.
 * Higher 16bit is the length of the array.
 */
#define __get_dynamic_array(args, field) ((void *)args + (args->__data_loc_##field & 0xffff))
#define __get_dynamic_array_len(args, field) ((args->__data_loc_##field >> 16) & 0xffff)
#define __get_str(args, field) ((char *)__get_dynamic_array(args, field))

static bool __always_inline comm_diff(const char *a, const char *b, u32 strlen)
{
	char diff;
	int i;
#pragma clang loop unroll(full)
	for (i = 0; i < 16; i++) {
		if (a[i] != b[i])
			goto end;
	}

end:
	if (i > strlen)
		diff = false;
	else
		diff = true;

	return diff;
}

#endif
