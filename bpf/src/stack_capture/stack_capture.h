// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

/**
 * @file stack_capture.h
 * @brief Internal configuration types for stack_capture module.
 */
#ifndef CPA_BPF_STACK_CAPTURE_INTERNAL_H
#define CPA_BPF_STACK_CAPTURE_INTERNAL_H

#include <stdbool.h>

struct stack_capture_config {
	unsigned int stack_offset;
	unsigned int page_size;
	unsigned int stack_capture_size;
	unsigned long long irqoff_threshold;
	unsigned long task_max;

	unsigned long __per_cpu_offset_addr;
	unsigned long perf_throttled_count_off;
	unsigned long actual_perf_throttled_count_addr;

	int is_timer;
	int pid;
	char comm[16];
	int comm_len;
	bool only_kernel;
};

#endif
