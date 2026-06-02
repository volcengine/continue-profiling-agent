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
#include "stack_capture.h"

// will change max_entries in .c
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
	__type(value, struct stack_capture_config);
} percpu_config SEC(".maps"); // us

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} perf_output_events SEC(".maps");

// in 64k system, still use 4096
#define PAGE_SIZE 4096
#define MAX_STACK_CAPTURE_PAGES (MAX_STACK_EVENT_USER_STACK_SIZE / PAGE_SIZE)

#define SHOULD_RECORD_PID_COMM(now_pid, now_tgid, now_comm)                                                                                                                                                                                                    \
	((config->pid == 0 && config->comm[0] == '\0') || (config->pid != 0 && (config->pid == now_pid || config->pid == now_tgid)) || (config->comm[0] != '\0' && comm_diff(config->comm, now_comm, config->comm_len) == 0))

#define SHOULD_RECORD_PID(now_pid, now_tgid) ((config->pid == 0) || (config->pid != 0 && (config->pid == now_pid || config->pid == now_tgid)))

static __always_inline bool should_record(void)
{
	u32 zero = 0;
	struct stack_capture_config *config = NULL;
	config = bpf_map_lookup_elem(&percpu_config, &zero);
	if (config == NULL)
		return false;

	unsigned long pid_res = bpf_get_current_pid_tgid();
	unsigned int pid = 0, tgid = 0;
	pid = pid_res >> 32;
	tgid = pid_res;

	char comm[TASK_COMM_LEN];
	__builtin_memset(comm, 0, TASK_COMM_LEN);
	bpf_get_current_comm(&comm, TASK_COMM_LEN);
	if (!SHOULD_RECORD_PID_COMM(pid, tgid, comm))
		return false;

	return true;
}

static __always_inline int read_user_stack(struct stack_capture_config *config, u8 *stack, u64 sp)
{
	int ret = 0;
	u32 read_size = 0;
	u32 copy_size = 0;
	u32 stack_capture_size = MAX_STACK_EVENT_USER_STACK_SIZE;
	u64 stack_page_start = sp & ~(PAGE_SIZE - 1);
	int i = 0;

	if (config->stack_capture_size < stack_capture_size)
		stack_capture_size = config->stack_capture_size;

		/*
	 * Copy bounded 4KiB chunks only. This keeps verifier bounds simple,
	 * honors the configured cap, and stops before the task address limit.
	 */
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
#define KERNEL_PF_EXITING 0x00000004

#if defined(__CPA_BPF_ARCH_arm64)
#define read_pt_regs user_pt_regs
#elif defined(__CPA_BPF_ARCH_x86)
#define read_pt_regs pt_regs
#endif

static __always_inline void update_irq_timestamp(u64 *time, unsigned long perf_throttled_count)
{
	u32 zero = 0;
	if (perf_throttled_count > 0) {
		u64 zero_time = 0;
		bpf_map_update_elem(&irq_stamp, &zero, &zero_time, BPF_ANY);
	} else {
		bpf_map_update_elem(&irq_stamp, &zero, time, BPF_ANY);
	}
}

static __always_inline int __stack_capture(bool is_timer, struct bpf_perf_event_data *ctx)
{
	u32 zero = 0;
	struct stack_event *event;
	unsigned int pid = 0, tid = 0;
	struct stack_capture_config *config = NULL;
	u64 *last_cap = NULL;
	struct read_pt_regs *regs = NULL;
	u64 time = bpf_ktime_get_ns();
	unsigned int flags = 0;
	u8 *content = NULL;
	int cpu = bpf_get_smp_processor_id();

	config = bpf_map_lookup_elem(&percpu_config, &zero);
	if (config == NULL)
		return 0;

	unsigned long perf_throttled_count = 0;

	/* Lazily resolve and cache this per-CPU kernel counter address. */
	if (config->actual_perf_throttled_count_addr == 0)
		config->actual_perf_throttled_count_addr = get_percpu_addr(config->__per_cpu_offset_addr, cpu, config->perf_throttled_count_off);

	if (config->actual_perf_throttled_count_addr != 0)
		bpf_probe_read_kernel(&perf_throttled_count, sizeof(unsigned long), (const void *)config->actual_perf_throttled_count_addr);

	pid = bpf_get_current_pid_tgid() >> 32;
	if (pid == 0) {
		update_irq_timestamp(&time, perf_throttled_count);
		return 0;
	}

	tid = bpf_get_current_pid_tgid();
	if (is_timer) {
		if (!SHOULD_RECORD_PID(tid, pid)) {
			update_irq_timestamp(&time, perf_throttled_count);
			return 0;
		}
	}

	content = bpf_map_lookup_elem(&stack_content_buf, &cpu);
	if (!content) {
		update_irq_timestamp(&time, perf_throttled_count);
		return 0;
	}

	event = (struct stack_event *)content;
	content = content + sizeof(struct stack_event);

	struct task_struct *cur = (struct task_struct *)bpf_get_current_task();

	event->pid = pid;
	event->ustack_fp_size = 0;
	event->kstack_sz = 0;
	event->user_mode = 0;
	event->stack_size = 0;
	event->sp = 0;
	event->cgid = task_cgroup_id(cur);
	event->cpu = bpf_get_smp_processor_id();
	event->timestamp = time;
	bpf_get_current_comm(&event->comm, TASK_COMM_LEN);
	fill_kernel_stack(ctx, event);
	event->type = 0;

	if (config->irqoff_threshold != 0 && is_timer) {
		last_cap = bpf_map_lookup_elem(&irq_stamp, &zero);
		// threshold is us, 1.1 to ignore little diff
		if (last_cap && *last_cap != 0 && (event->timestamp - *last_cap) > config->irqoff_threshold * 1100) {
			event->diff_ns = event->timestamp - *last_cap - (config->irqoff_threshold * 1000);
			event->type |= STACK_EVENT_IRQOFF;
		}
		update_irq_timestamp(&time, perf_throttled_count);
	}

	flags = BPF_CORE_READ(cur, flags);

	if (flags & KERNEL_PF_KTHREAD) {
		event->type |= STACK_EVENT_KTHREAD;
		event->stack_size = 0;
		goto send_event;
	}

	struct task_struct *group = BPF_CORE_READ(cur, group_leader);
	event->unique_id = BPF_CORE_READ(group, start_time);
	BPF_CORE_READ_STR_INTO(&event->group_comm, group, comm);

	event->type |= STACK_EVENT_COMMON;

	if (flags & KERNEL_PF_EXITING) {
		event->sp = 0;
		event->stack_size = 0;
		goto send_event;
	}

	/*
	 * CO-RE probes helper availability at load time. Older targets simply
	 * omit the FP stack rather than failing the whole capture path.
	 */
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

	/* User registers live at the architecture-specific task stack tail. */
	u64 user_pt_regs_ptr = stack_ptr + config->stack_offset - bpf_core_type_size(struct pt_regs);
	bpf_probe_read_kernel(&(event->regs), sizeof(struct read_pt_regs), (const void *)user_pt_regs_ptr);

	regs = (struct read_pt_regs *)&(event->regs);
	event->user_mode = user_mode(*regs);

	if (config->only_kernel)
		goto send_event;

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

SEC("tracepoint")
int stack_capture_tp(struct bpf_perf_event_data *ctx)
{
	if (should_record())
		return __stack_capture(false, ctx);
	return 0;
}

SEC("perf_event")
int stack_capture_timer(struct bpf_perf_event_data *ctx)
{
	return __stack_capture(true, ctx);
}

SEC("kprobe")
int stack_capture_kprobe(struct bpf_perf_event_data *ctx)
{
	if (should_record())
		return __stack_capture(false, ctx);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
