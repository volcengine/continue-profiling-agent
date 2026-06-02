// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

/**
 * @file offcpu_capture.h
 * @brief Internal configuration types for offcpu_capture module.
 */
#ifndef CPA_BPF_OFFCPU_CAPTURE_INTERNAL_H
#define CPA_BPF_OFFCPU_CAPTURE_INTERNAL_H

struct offcpu_capture_config {
	unsigned int stack_offset;
	unsigned int page_size;
	unsigned int offcpu_capture_size;
	unsigned long long irqoff_threshold;
	unsigned long task_max;
	int pid;
	char comm[16];
	int comm_len;
};

#endif
