// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

/**
 * @file perf_stack_capture.h
 * @brief User space perf-based stack capture utilities.
 *
 * This API provides a low-overhead user space stack capture implementation based
 * on Linux perf events. It is used by CPA in "perf" backend mode.
 */
#ifndef CPA_BPF_PERF_STACK_CAPTURE_H
#define CPA_BPF_PERF_STACK_CAPTURE_H

#include <cpa_bpf/bpf_event.h>
#include <stdint.h>

#define MAX_STACK_DEPTH 127
#define MAX_USER_STACK_DUMP_SIZE (60 * 1024)
#define PERF_STACK_CAPTURE_PAGE_CNT 64

/**
 * PERF stack capture event payload.
 */
struct perf_stack_event {
	unsigned long time;
	unsigned int pid;
	unsigned int tid;
	unsigned int cpu;
	unsigned long cgid;
	char comm[TASK_COMM_LEN];
	unsigned long rsp;
	unsigned long rip;
	unsigned long rbp;
#if defined(__CPA_BPF_ARCH_arm64)
	unsigned long lr;
#endif
	unsigned long kstack_sz;
	unsigned long kstack[MAX_STACK_DEPTH];
	unsigned long ustack_sz;
	unsigned long ustack[MAX_STACK_DEPTH];
	unsigned long ustack_raw_sz;
	char ustack_raw[MAX_USER_STACK_DUMP_SIZE + 4096];
};

typedef void (*perf_event_handler_fn)(struct perf_stack_event *event, void *data);

/**
 * Opaque capture context.
 */
struct perf_stack_capture_ctx;

/**
 * struct perf_stack_capture_stats - perf mmap transport counters
 * @lost_events: lost records observed in the perf mmap stream
 */
struct perf_stack_capture_stats {
	uint64_t lost_events;
};

/**
 * Register perf backend capture callbacks and return context.
 */
struct perf_stack_capture_ctx *perf_setup_stack_capture_event(int sample_period, perf_event_handler_fn handler, void *handler_data);

/**
 * Tear down perf capture context.
 */
void perf_stack_capture_cleanup(struct perf_stack_capture_ctx *ctx);

/**
 * perf_stack_capture_get_stats - snapshot perf mmap transport counters
 * @ctx: capture context
 * @stats: destination statistics object
 */
void perf_stack_capture_get_stats(struct perf_stack_capture_ctx *ctx, struct perf_stack_capture_stats *stats);

#endif
