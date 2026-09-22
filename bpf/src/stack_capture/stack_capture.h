// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

/**
 * @file stack_capture.h
 * @brief Internal configuration types shared by the BPF program and the
 *        userspace loader of the stack_capture module.
 */
#ifndef CPA_BPF_STACK_CAPTURE_INTERNAL_H
#define CPA_BPF_STACK_CAPTURE_INTERNAL_H

#include <stdbool.h>

#define STACK_CAPTURE_COMM_LIMIT_MAX_ENTRIES 40960
#define STACK_CAPTURE_DEFAULT_COMM_STACK_LIMIT_SIZE 4096

struct stack_capture_config {
unsigned int stack_offset;
unsigned int page_size;
unsigned int stack_capture_size;
unsigned long long irqoff_threshold;
/* When nonzero, abort a long user-stack copy after this many nanoseconds. */
unsigned long long bpf_exec_time_guard_ns;
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

/* Key of the userspace-managed slow-comm user-stack limit map. */
struct stack_capture_comm_key {
char comm[16];
};

struct stack_capture_comm_limit_stat {
unsigned int entries;
unsigned int capacity;
};

/*
 * Userspace manages the comm -> forced user-stack-size map. A comm that
 * repeatedly trips the BPF execution-time guard is limited to a small
 * payload so later samples stay cheap.
 */
int stack_capture_set_comm_stack_limit(const char *comm, unsigned int stack_size);
int stack_capture_clear_comm_stack_limits(void);
int stack_capture_get_comm_stack_limit_stat(struct stack_capture_comm_limit_stat *stat);

#endif
