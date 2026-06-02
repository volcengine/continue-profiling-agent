// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <linux/version.h>
#include "core_fixes.bpf.h"

#include <cpa_bpf/bpf_event.h>
#include "offcpu_capture.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 40960);
	__uint(key_size, sizeof(unsigned int));
	__uint(value_size, sizeof(unsigned long));
} pid_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, char[STACK_EVENT_MAX_PAYLOAD]);
} stack_content_buf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} irq_stamp SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct offcpu_capture_config);
} percpu_config SEC(".maps"); // us

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} perf_output_events SEC(".maps");

// in 64k system, still use 4096
#define PAGE_SIZE 4096
#define MAX_STACK_CAPTURE_PAGES (MAX_STACK_EVENT_USER_STACK_SIZE / PAGE_SIZE)

static __always_inline int read_user_stack(struct offcpu_capture_config *config, u8 *stack, u64 sp)
{
	int ret = 0;
	u32 read_size = 0;
	u32 copy_size = 0;
	u32 stack_capture_size = MAX_STACK_EVENT_USER_STACK_SIZE;
	u64 stack_page_start = sp & ~(PAGE_SIZE - 1);
	int i = 0;

	if (config->offcpu_capture_size < stack_capture_size)
		stack_capture_size = config->offcpu_capture_size;

#pragma clang loop unroll(full)
	for (i = 0; i < MAX_STACK_CAPTURE_PAGES; i++) {
		if (read_size >= stack_capture_size)
			break;
		if (stack_page_start >= config->task_max)
			break;
		copy_size = PAGE_SIZE;

		ret = bpf_probe_read_user(stack, copy_size, (u8 *)stack_page_start);
		if (ret) {
			break;
		} else {
			stack_page_start += PAGE_SIZE;
			read_size += copy_size;
			stack += copy_size;
		}
	}

	return read_size;
}

static __always_inline void fill_kernel_stack(struct bpf_perf_event_data *ctx, struct stack_event *event)
{
	int kstack_bytes = bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);

	if (kstack_bytes > 0)
		event->kstack_sz = kstack_bytes / sizeof(unsigned long);
	else
		event->kstack_sz = 0;
}

#define KERNEL_PF_KTHREAD 0x00200000

#if defined(__CPA_BPF_ARCH_arm64)
#define read_pt_regs user_pt_regs
#elif defined(__CPA_BPF_ARCH_x86)
#define read_pt_regs pt_regs
#endif

#define SHOULD_RECORD(now_pid, now_tgid, now_comm)                                                                                                                                                                                                             \
	((config->pid == 0 && config->comm[0] == '\0') || (config->pid != 0 && (config->pid == now_pid || config->pid == now_tgid)) || (config->comm[0] != '\0' && comm_diff(config->comm, now_comm, config->comm_len) == 0))

static __always_inline int oncpu(void *ctx, struct task_struct *prev, struct task_struct *curr);

SEC("kprobe/finish_task_switch")
int BPF_KPROBE(finish_task_switch_k, struct task_struct *prev)
{
	struct task_struct *curr = (struct task_struct *)bpf_get_current_task();
	return oncpu(ctx, prev, curr);
}

static __always_inline int oncpu(void *ctx, struct task_struct *prev, struct task_struct *cur)
{
	u32 zero = 0;
	struct stack_event *event;
	unsigned int pid = 0, tgid = 0;
	struct offcpu_capture_config *config = NULL;
	struct read_pt_regs *regs = NULL;
	unsigned int flags = 0;
	u8 *content = NULL;
	unsigned long time = bpf_ktime_get_ns();
	int cpu = bpf_get_smp_processor_id();

	char comm[TASK_COMM_LEN];

	/* get config */
	config = bpf_map_lookup_elem(&percpu_config, &zero);
	if (config == NULL)
		return 0;

	unsigned long *prev_time = NULL;
	long delta = 0;

	/* record pid offcpu time */
	pid = BPF_CORE_READ(prev, pid);
	tgid = BPF_CORE_READ(prev, tgid);
	__builtin_memset(comm, 0, TASK_COMM_LEN);
	BPF_CORE_READ_STR_INTO(&comm, prev, comm);

	if (SHOULD_RECORD(pid, tgid, comm))
		bpf_map_update_elem(&pid_start, &pid, &time, BPF_ANY);

	/* check oncpu pid should record */
	unsigned long pid_res = bpf_get_current_pid_tgid();
	pid = pid_res;
	tgid = pid_res >> 32;
	__builtin_memset(comm, 0, TASK_COMM_LEN);
	bpf_get_current_comm(&comm, TASK_COMM_LEN);

	if (!SHOULD_RECORD(pid, tgid, comm))
		return 0;

	prev_time = bpf_map_lookup_elem(&pid_start, &pid);
	if (!prev_time || *prev_time == 0)
		return 0;

	bpf_map_delete_elem(&pid_start, &pid);

	delta = time - *prev_time;
	if (delta <= 0)
		return 0;

	content = bpf_map_lookup_elem(&stack_content_buf, &cpu);
	if (!content)
		return 0;

	event = (struct stack_event *)content;
	content = content + sizeof(struct stack_event);

	/*
	 * offcpu keeps the blocked thread TID in @pid and preserves the process
	 * TGID in @cgid so process-level metadata remains stable for all
	 * blocking threads in the same task group.
	 */
	event->pid = pid;
	event->cgid = tgid;
	event->cpu = cpu;
	event->diff_ns = delta;
	event->timestamp = time;
	__builtin_memcpy(event->comm, comm, TASK_COMM_LEN);
	event->ustack_fp_size = 0;
	event->kstack_sz = 0;
	event->user_mode = 0;
	event->stack_size = 0;
	event->sp = 0;
	fill_kernel_stack(ctx, event);
	event->type = 0;

	flags = BPF_CORE_READ(cur, flags);

	if (flags & KERNEL_PF_KTHREAD) {
		event->type |= STACK_EVENT_KTHREAD;
		goto send_event;
	}

	struct task_struct *group = BPF_CORE_READ(cur, group_leader);
	event->unique_id = BPF_CORE_READ(group, start_time);
	BPF_CORE_READ_STR_INTO(&event->group_comm, group, comm);

	event->type |= STACK_EVENT_COMMON;

	if (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_stack)) {
		int ustack_fp_size = bpf_get_stack(ctx, event->ustack_fp, sizeof(event->ustack_fp), BPF_F_USER_STACK);

		if (ustack_fp_size > 0)
			event->ustack_fp_size = ustack_fp_size;
		else
			event->ustack_fp_size = 0;
	} else {
		event->ustack_fp_size = 0;
	}

	u64 stack_ptr = (u64)BPF_CORE_READ(cur, stack);
	if (!stack_ptr) {
		event->sp = 0;
		goto send_event;
	}

	u64 user_pt_regs_ptr = stack_ptr + config->stack_offset - bpf_core_type_size(struct pt_regs);
	bpf_probe_read_kernel(&(event->regs), sizeof(struct read_pt_regs), (const void *)user_pt_regs_ptr);

	regs = (struct read_pt_regs *)&(event->regs);
	event->user_mode = user_mode(*regs);

	event->sp = BPF_CORE_READ(regs, sp);
	if (event->sp >= config->task_max)
		goto send_event;

	event->stack_size = read_user_stack(config, content, event->sp);

send_event:

	event->bpf_exec_time = bpf_ktime_get_ns() - time;

	if (event->stack_size > MAX_STACK_EVENT_USER_STACK_SIZE)
		event->stack_size = MAX_STACK_EVENT_USER_STACK_SIZE;
	bpf_perf_event_output(ctx, &perf_output_events, BPF_F_CURRENT_CPU, (u8 *)event, sizeof(struct stack_event) + event->stack_size);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
