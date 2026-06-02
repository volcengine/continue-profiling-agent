// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

/**
 * @file bpf_event.h
 * @brief Shared event payload types and callbacks for CPA user space.
 *
 * This header defines the user space view of event records emitted from eBPF
 * programs and delivered through perf/ring buffers. The same layouts are used
 * by active capture modules.
 */
#ifndef CPA_BPF_BPF_EVENT_H
#define CPA_BPF_BPF_EVENT_H

#include <stdbool.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

/**
 * Callback for payload delivered by BPF perf maps.
 *
 * @param event Pointer to the raw event payload.
 * @param size Size of the payload in bytes.
 * @param user_ctx User context pointer passed when registering the callback.
 */
typedef void (*bpf_event_process_fn)(void *event, unsigned int size, void *user_ctx);

#define STACK_CAPTURE_SIZE 8192

#ifdef __CPA_BPF_ARCH_x86
#define PT_REGS_SIZE 168
#elif defined(__CPA_BPF_ARCH_arm64)
#define PT_REGS_SIZE 272
#endif

enum stack_event_type {
	STACK_EVENT_COMMON_BIT = 0,
	STACK_EVENT_KTHREAD_BIT,
	STACK_EVENT_IRQOFF_BIT,
	STACK_EVENT_FP_BACKTRACE_BIT,
	STACK_EVENT_MAX_BIT,
};

#define STACK_EVENT_COMMON (1U << STACK_EVENT_COMMON_BIT)
#define STACK_EVENT_KTHREAD (1U << STACK_EVENT_KTHREAD_BIT)
#define STACK_EVENT_IRQOFF (1U << STACK_EVENT_IRQOFF_BIT)
#define STACK_EVENT_FP_BACKTRACE (1U << STACK_EVENT_FP_BACKTRACE_BIT)

#define MAX_FP_STACK_LEVEL (128 - 1)
#define MAX_KERNEL_STACK_LEVEL MAX_FP_STACK_LEVEL
#define STACK_EVENT_MAX_PAYLOAD (64 * 1024)
/*
 * Keep one full page of slack in the scratch buffer. User stacks are copied in
 * page-sized chunks from BPF, and the verifier requires the worst-case copy to
 * stay within the map value bounds on every path. The total event plus copied
 * user stack must also remain below the 64 KiB perf-event payload ceiling.
 */
#define MAX_STACK_EVENT_USER_STACK_SIZE (56 * 1024)

/**
 * struct stack_event - stack capture event payload emitted by BPF
 * @pid: sampler-specific task identifier slot
 *       stack_capture stores TGID here. offcpu_capture stores the blocked
 *       thread TID because the register snapshot is thread-scoped.
 * @cgid: secondary metadata slot
 *        stack_capture stores cgroup id here. offcpu_capture stores TGID
 *        here so the userspace path still has both thread and process
 *        identity until the payload grows an explicit tid field.
 */
struct stack_event {
	unsigned int pid;
	unsigned long cgid;
	unsigned long timestamp;
	unsigned int type;
	unsigned long unique_id;
	unsigned long diff_ns;
	unsigned int cpu;
	unsigned int bpf_exec_time;
	unsigned short kstack_sz;
	unsigned char user_mode;
	unsigned char reserved0;
	unsigned long kstack[MAX_KERNEL_STACK_LEVEL];
	unsigned int stack_size;
	char comm[TASK_COMM_LEN];
	char group_comm[TASK_COMM_LEN];
	unsigned long ustack_fp[MAX_FP_STACK_LEVEL];
	unsigned int ustack_fp_size;
	unsigned char regs[PT_REGS_SIZE];
	unsigned long sp;
};

_Static_assert(sizeof(struct stack_event) + MAX_STACK_EVENT_USER_STACK_SIZE <= STACK_EVENT_MAX_PAYLOAD, "stack_event payload exceeds perf buffer limit");

/**
 * Process-exit notification payload.
 */
struct process_exit_event {
	unsigned int pid;
	unsigned long ts;
};

#endif
