// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CPA_BPF_H
#define CPA_BPF_H

#include <stdbool.h>

#include <cpa_bpf/bpf_event.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/**
 * @file cpa_bpf.h
 * @brief Front-end BPF module registration and capture API.
 */

/* Exported capture modules. */
#define __BPF_MODULE(FN)                                                                                                                                                                                                                                       \
	FN(stack_capture)                                                                                                                                                                                                                                      \
	FN(offcpu_capture)                                                                                                                                                                                                                                     \
	FN(process_exit)                                                                                                                                                                                                                                       \
	/* */

#define __BPF_ENUM_FN(x) BPF_MODULE_##x,
enum bpf_module_id {
	__BPF_MODULE(__BPF_ENUM_FN) __BPF_MODULE_MAX_ID,
};
#undef __BPF_ENUM_FN

/**
 * struct cpa_bpf_init_options - top-level BPF runtime initialization options
 * @mask: bitmask of modules to enable during initial setup
 * @btf_path: optional external BTF path to prefer over bundled CO-RE data
 */
struct cpa_bpf_init_options {
	unsigned long mask;
	const char *btf_path;
};

/* Enable verbose libbpf/module diagnostics on stderr. */
void set_cpa_bpf_verbose(void);

/* Initialize the shared BPF runtime and enable the requested modules. */
int init_bpf(struct cpa_bpf_init_options *options);

/* Tear down all loaded modules and release shared BPF state. */
void free_bpf(void);

/* Reconcile the active module mask with @mask. */
int bpf_module_ctl(unsigned long mask);

/* Return the currently enabled module bitmask. */
unsigned long get_bpf_mask(void);

/**
 * struct stack_capture_ctx - userspace context for on-CPU BPF capture setup
 * @probe_name: optional probe selector, or %NULL for timer sampling
 * @only_kernel: skip user stack collection when set
 * @pid: pid/tgid filter, or 0 for all tasks
 * @comm: task comm filter, zero-terminated when present
 */
struct stack_capture_ctx {
	const char *probe_name;
	bool only_kernel;
	int pid;
	char comm[TASK_COMM_LEN];
};

/* Clamp the copied user-stack payload for on-CPU capture. */
int set_stack_capture_size(int size);

/* Create the on-CPU stack capture pipeline. */
int setup_stack_capture_event(int freq, bpf_event_process_fn fn, struct stack_capture_ctx *user_ctx);

/**
 * struct offcpu_capture_ctx - userspace context for off-CPU capture setup
 * @pid: pid/tgid filter, or 0 for all tasks
 * @comm: task comm filter, zero-terminated when present
 */
struct offcpu_capture_ctx {
	int pid;
	char comm[TASK_COMM_LEN];
};

/* Clamp the copied user-stack payload for off-CPU capture. */
int set_offcpu_capture_size(int size);

/* Create the off-CPU capture pipeline. */
int setup_offcpu_capture_event(int freq, bpf_event_process_fn fn, struct offcpu_capture_ctx *user_ctx);

/* Subscribe to process-exit notifications used for pid-context retirement. */
int setup_process_exit_event(bpf_event_process_fn fn);

#endif /* CPA_BPF_H */
