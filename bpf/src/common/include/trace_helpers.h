/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
// Copyright (c) 2020 Wenbo Zhang
// Copyright (c) 2024 Bytedance
//
// Based on ksyms improvements from Andrii Nakryiko, add more helpers.
// 28-Feb-2020   Wenbo Zhang   Created this.
// 11-Mar-2024   Yuchen Zhang  Add more helpers.
#ifndef CPA_BPF_TRACE_HELPERS_H
#define CPA_BPF_TRACE_HELPERS_H

/**
 * @file trace_helpers.h
 * @brief User space helpers used by CPA modules for kernel feature probing.
 */

#include <stdbool.h>

/**
 * Time and stack depth constants used by perf/kprobe helpers.
 */
#define MSEC_PER_SEC 1000UL
#define NSEC_PER_SEC 1000000000ULL

#define PERF_MAX_STACK_DEPTH 127

/**
 * Check whether a kernel function name exists before probing.
 * The name of a kernel function to be attached to may be changed between
 * kernel releases. This helper is used to confirm whether the target kernel
 * uses a certain function name before attaching.
 *
 * It is achieved by scaning
 * 	/sys/kernel/debug/tracing/available_filter_functions
 * If this file does not exist, it fallbacks to parse /proc/kallsyms,
 * which is slower.
 */
bool kprobe_exists(const char *name);

bool vmlinux_btf_exists(void);
bool module_btf_exists(const char *mod);
bool kernel_config_enabled(const char *config);
char *kernel_config_value(const char *config);

unsigned long get_task_size_max(void);

char *find_kprobe_functions(const char *func);

/**
 * find_ksyms_addr - find addresses of exact kernel symbols
 * @names: array of symbol names to match (full token match)
 * @addrs: output addresses; set to 0 if not found
 * @count: number of entries in @names and @addrs
 *
 * Scans /proc/kallsyms and matches exact tokens.
 * Return: number of matches found, or -1 on error.
 */
int find_ksyms_addr(const char *names[], unsigned long *addrs, int count);

#endif
