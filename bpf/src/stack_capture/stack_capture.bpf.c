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

/*
 * Kernel-only mode emits a fixed-size stack_event with no user payload.
 * A separate value-sized map keeps the perf output length constant so old
 * verifiers can prove the bound instead of scaling by a runtime scalar.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct stack_event);
} kernel_event_buf SEC(".maps");

/*
 * Slow comms (populated from userspace after an execution-time guard
 * trip) get a forced smaller user-stack payload keyed by task comm.
 */
struct {
__uint(type, BPF_MAP_TYPE_HASH);
__uint(max_entries, STACK_CAPTURE_COMM_LIMIT_MAX_ENTRIES);
__type(key, struct stack_capture_comm_key);
__type(value, u32);
} comm_stack_limit SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} irq_stamp SEC(".maps");

/*
 * One-shot marker: when perf overflows while throttled, the next overflow
 * interval is delivered inflated post-unthrottle and must not be reported as
 * IRQ-off. The current overflow is kept (it may be the first sample after a
 * real IRQ-off span); arm the drop for the following interval instead.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} irqoff_post_throttle_drop SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct stack_capture_config);
} percpu_config SEC(".maps"); // us

#ifdef CPA_USE_RINGBUF
#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF 27
#endif
/*
 * Ring buffer datapath: userspace resizes events_rb before load.
 */
struct {
__uint(type, BPF_MAP_TYPE_RINGBUF);
__uint(max_entries, 16 * 1024 * 1024);
} events_rb SEC(".maps");

struct {
__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
__uint(max_entries, 1);
__type(key, u32);
__type(value, u64);
} ringbuf_drops SEC(".maps");

#define CPA_EMIT_EVENT(raw_ctx, ev, sz)                          \
	({                                                             \
		if (bpf_ringbuf_output(&events_rb, (ev), (sz), 0) != 0) {  \
			u32 cpa_z0 = 0;                                          \
			u64 *cpa_dc = bpf_map_lookup_elem(&ringbuf_drops, &cpa_z0); \
			if (cpa_dc)                                             \
				__sync_fetch_and_add(cpa_dc, 1);                       \
		}                                                          \
	})
#else
struct {
__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
__uint(key_size, sizeof(u32));
__uint(value_size, sizeof(u32));
} perf_output_events SEC(".maps");

#define CPA_EMIT_EVENT(raw_ctx, ev, sz) \
	bpf_perf_event_output((raw_ctx), &perf_output_events, BPF_F_CURRENT_CPU, (ev), (sz))
#endif

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

static __always_inline u32 stack_capture_effective_size(struct stack_capture_config *config)
{
	struct stack_capture_comm_key key = { 0 };
	u32 size = MAX_STACK_EVENT_USER_STACK_SIZE;
	u32 *limit;

	if (config->stack_capture_size < size)
		size = config->stack_capture_size;

	bpf_get_current_comm(&key.comm, sizeof(key.comm));
	limit = bpf_map_lookup_elem(&comm_stack_limit, &key);
	if (limit && *limit < size)
		size = *limit;

	return size;
}

static __always_inline int read_user_stack(struct stack_capture_config *config, u8 *stack, u64 sp)
{
	int ret = 0;
	u32 read_size = 0;
	u32 copy_size = 0;
	u32 stack_capture_size = stack_capture_effective_size(config);
	u64 stack_page_start = sp & ~(PAGE_SIZE - 1);
	u64 copy_start_ns = bpf_ktime_get_ns();
	int i = 0;

		/*
		 * Copy bounded 4KiB chunks only. This keeps verifier bounds simple,
		 * honors the configured/forced cap, and stops before the task address
		 * limit. The execution-time guard aborts a copy that runs too long
		 * (slow or driver-backed mappings) so one task cannot stall sampling.
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
			if (config->bpf_exec_time_guard_ns != 0 &&
			    bpf_ktime_get_ns() - copy_start_ns >
				    config->bpf_exec_time_guard_ns)
				break;
		}
	}

	return read_size;
}

static __always_inline void fill_kernel_stack(void *raw_ctx, struct stack_event *event)
{
	int kstack_bytes = bpf_get_stack(raw_ctx, event->kstack, sizeof(event->kstack), 0);

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

/*
 * Whether the current sample must be suppressed as a post-throttle
 * artifact. A throttled overflow arms a one-shot drop of the NEXT
 * overflow; while throttling keeps overflows coming the marker stays
 * armed and the current sample is kept (it may be a real IRQ-off span).
 */
static __always_inline bool
stack_capture_consume_post_throttle_irqoff(unsigned long perf_throttled_count)
{
	u32 zero = 0;
	u32 *drop_next;
	bool drop_current = false;

	drop_next = bpf_map_lookup_elem(&irqoff_post_throttle_drop, &zero);
	if (drop_next) {
		if (perf_throttled_count > 0) {
			*drop_next = 1;
			return false;
		}
		drop_current = *drop_next != 0;
		*drop_next = 0;
	}

	return drop_current;
}

/* Record the real timestamp as the new IRQ-off baseline. */
static __always_inline void advance_irq_timestamp(u64 *time)
{
	u32 zero = 0;

	bpf_map_update_elem(&irq_stamp, &zero, time, BPF_ANY);
}

/*
 * Baseline update for filtered/unemitted samples and buffer-miss paths:
 * the timestamp still advances (otherwise a later real span is measured
 * from a stale stamp), but filtered samples never consume a pending drop
 * marker. When the filtering sample establishes the new IRQ-timer baseline
 * with no throttle in flight, any earlier marker is obsolete.
 */
static __always_inline void
advance_filtered_irq_timestamp(u64 *time, bool is_irq_timer,
			       unsigned long perf_throttled_count)
{
	u32 zero = 0;
	u32 *drop_next;

	advance_irq_timestamp(time);
	if (!is_irq_timer || perf_throttled_count > 0)
		return;

	drop_next = bpf_map_lookup_elem(&irqoff_post_throttle_drop, &zero);
	if (drop_next)
		*drop_next = 0;
}

static __always_inline int __stack_capture(void *raw_ctx, bool is_timer,
				  bool is_coredump, int coredump_sig, int coredump_code)
{
	struct bpf_perf_event_data *ctx = (struct bpf_perf_event_data *)raw_ctx;
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
		advance_filtered_irq_timestamp(
			&time, is_timer && config->irqoff_threshold != 0,
			perf_throttled_count);
		return 0;
	}

	tid = bpf_get_current_pid_tgid();
	if (is_timer) {
		char timer_comm[TASK_COMM_LEN] = {};
		bpf_get_current_comm(&timer_comm, sizeof(timer_comm));
		{
			int tcd = comm_diff(config->comm, timer_comm, config->comm_len);
			char cfg0 = config->comm[0];
			bool match_comm = cfg0 != 0 && tcd == 0;
			bool match_pid = config->pid != 0 &&
				(config->pid == tid || config->pid == pid);
			if (cfg0 == 0 && config->pid == 0)
				match_comm = true;
			if (!match_pid && !match_comm) {
			advance_filtered_irq_timestamp(
				&time, config->irqoff_threshold != 0,
				perf_throttled_count);
			return 0;
			}
		}
	}

	/*
	 * Kernel-only path: fixed-size event from a dedicated map, so the
	 * perf output length is the constant sizeof(struct stack_event) and
	 * never scales with a runtime stack_size scalar (verifier-safe on
	 * old kernels).
	 */
	if (config->only_kernel && !is_coredump) {
		content = bpf_map_lookup_elem(&kernel_event_buf, &cpu);
		if (!content) {
			advance_filtered_irq_timestamp(
				&time, is_timer && config->irqoff_threshold != 0,
				perf_throttled_count);
			return 0;
		}

		event = (struct stack_event *)content;
		/* Field-level reset (portable across BPF clangs). */
		event->ustack_fp_size = 0;
		event->user_mode = 0;
		event->reserved0 = 0;
		event->sp = 0;
		/*
		 * ustack_fp[] and regs[] are never written on the kernel-only
		 * path, and userspace zero-fills each per-CPU buffer before
		 * attach; avoid large zero loops that old BPF clangs lower to
		 * an unsupported memset builtin.
		 */

		struct task_struct *cur = (struct task_struct *)bpf_get_current_task();

		event->pid = pid;
		event->cgid = task_cgroup_id(cur);
		event->cpu = bpf_get_smp_processor_id();
		event->timestamp = time;
		bpf_get_current_comm(&event->comm, TASK_COMM_LEN);
		fill_kernel_stack(ctx, event);
		event->type = 0;
		event->signal = 0;
		event->signal_code = 0;
		if (is_coredump) {
			event->type |= STACK_EVENT_COREDUMP;
			event->signal = coredump_sig;
			event->signal_code = coredump_code;
		}

		if (config->irqoff_threshold != 0 && is_timer) {
			bool drop_irqoff =
				stack_capture_consume_post_throttle_irqoff(
				perf_throttled_count);
			last_cap = bpf_map_lookup_elem(&irq_stamp, &zero);
			if (!drop_irqoff && last_cap && *last_cap != 0 && (event->timestamp - *last_cap) > config->irqoff_threshold * 1100) {
				event->diff_ns = event->timestamp - *last_cap - (config->irqoff_threshold * 1000);
				event->type |= STACK_EVENT_IRQOFF;
			}
			advance_irq_timestamp(&time);
		}

		flags = BPF_CORE_READ(cur, flags);
		if (flags & KERNEL_PF_KTHREAD) {
			event->type |= STACK_EVENT_KTHREAD;
		} else {
			struct task_struct *group = BPF_CORE_READ(cur, group_leader);
			event->unique_id = BPF_CORE_READ(group, start_time);
			BPF_CORE_READ_STR_INTO(&event->group_comm, group, comm);
			event->type |= STACK_EVENT_COMMON;
		}

		event->stack_size = 0;
		event->bpf_exec_time = bpf_ktime_get_ns() - time;
		CPA_EMIT_EVENT(ctx, (u8 *)event, sizeof(struct stack_event));
		return 0;
	}

	content = bpf_map_lookup_elem(&stack_content_buf, &cpu);
	if (!content) {
				advance_filtered_irq_timestamp(
			&time, is_timer && config->irqoff_threshold != 0,
			perf_throttled_count);
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
	event->signal = 0;
	event->signal_code = 0;
	if (is_coredump) {
		event->type |= STACK_EVENT_COREDUMP;
		event->signal = coredump_sig;
			event->signal_code = coredump_code;
	}

	if (config->irqoff_threshold != 0 && is_timer) {
		bool drop_irqoff =
			stack_capture_consume_post_throttle_irqoff(
			perf_throttled_count);
		last_cap = bpf_map_lookup_elem(&irq_stamp, &zero);
		// threshold is us, 1.1 to ignore little diff
		if (!drop_irqoff && last_cap && *last_cap != 0 && (event->timestamp - *last_cap) > config->irqoff_threshold * 1100) {
			event->diff_ns = event->timestamp - *last_cap - (config->irqoff_threshold * 1000);
			event->type |= STACK_EVENT_IRQOFF;
		}
		advance_irq_timestamp(&time);
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

	event->sp = BPF_CORE_READ(regs, sp);
	if (event->sp >= config->task_max)
		goto send_event;

	event->stack_size = read_user_stack(config, content, event->sp);

send_event:

	event->bpf_exec_time = bpf_ktime_get_ns() - time;

	if (event->stack_size > MAX_STACK_EVENT_USER_STACK_SIZE)
		event->stack_size = MAX_STACK_EVENT_USER_STACK_SIZE;
	CPA_EMIT_EVENT(ctx, (u8 *)event, sizeof(struct stack_event) + event->stack_size);

	return 0;
}

SEC("tracepoint")
int stack_capture_tp(struct bpf_perf_event_data *ctx)
{
	if (should_record())
		return __stack_capture(ctx, false, false, 0, 0);
	return 0;
}

SEC("perf_event")
int stack_capture_timer(struct bpf_perf_event_data *ctx)
{
	return __stack_capture(ctx, true, false, 0, 0);
}

SEC("kprobe")
int stack_capture_kprobe(struct bpf_perf_event_data *ctx)
{
	if (should_record())
		return __stack_capture(ctx, false, false, 0, 0);
	return 0;
}

/* signo/errno/code prefix shared by struct siginfo and kernel_siginfo. */
struct coredump_siginfo_prefix {
	int si_signo;
	int si_errno;
	int si_code;
};

SEC("kprobe/do_coredump")
int BPF_KPROBE(stack_capture_coredump)
{
	struct coredump_siginfo_prefix cd_info = {};
	int cd_sig = 0, cd_code = 0;
	const void *cd_siginfo = (const void *)PT_REGS_PARM1(ctx);

	if (!bpf_probe_read(&cd_info, sizeof(cd_info), cd_siginfo)) {
		cd_sig = cd_info.si_signo;
		cd_code = cd_info.si_code;
	}
	if (should_record())
		return __stack_capture(ctx, false, true, cd_sig, cd_code);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
