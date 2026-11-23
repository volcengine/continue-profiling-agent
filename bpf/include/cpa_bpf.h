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
	FN(target_ctl)                                                                                                                                                                                                                                         \
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
	/* BPF per-sample user-stack copy budget in ns; 0 disables. */
	unsigned long long bpf_exec_time_guard_ns;
	bool enable_coredump_capture;
	/* sample target_ctl's target set; @pid and @comm are then unused */
	bool target_dynamic;
};

/* Attach the do_coredump kprobe and tag crash-time samples. */
void stack_capture_set_coredump_capture(bool enabled);
/*
 * Attach the do_group_exit kprobe: one sample, tagged STACK_EVENT_EXIT_NONZERO,
 * per selected process that ends with a non-zero code.
 */
void stack_capture_set_exit_capture(bool enabled);
/*
 * Exit capture's own selection, compared at the exit: process names (each
 * shorter than 16 bytes, at most 8) or tgids (at most 16).  None: the global
 * selection applies.  -EINVAL on a bad list.
 */
int stack_capture_set_exit_targets(const char *const *comms, int n_comms, const unsigned int *pids, int n_pids);
/*
 * --pagefault: load the pagefault variant instead of the timer sampler.
 * Sampled new anonymous pages arrive as stack events through the regular
 * callback (stack_event::pf); address-space changes as struct
 * pf_release_event through @release_fn, on the poll thread.  The lost
 * callbacks are told the records the kernel dropped from full buffers.
 */
struct stack_capture_pagefault_cfg {
	bool enabled;
	unsigned int sample_pages;	/* a power of two, 1 to PF_SAMPLE_PAGES_MAX */
	unsigned long long salt;
	bpf_event_process_fn release_fn;
	bpf_event_lost_fn stack_lost_fn;
	bpf_event_lost_fn events_lost_fn;
};

void stack_capture_set_pagefault(const struct stack_capture_pagefault_cfg *cfg);
/* What the BPF side could not report; -ENOENT without a pagefault object. */
int stack_capture_pagefault_state(struct pf_state *out);

/* mode: 0=auto 1=perfbuf 2=ringbuf; ring_mb resizes the ring buffer. */
void stack_capture_set_datapath(int mode, unsigned int ring_mb);

/* Clamp the copied user-stack payload for on-CPU capture. */
int set_stack_capture_size(int size);

/* Create the on-CPU stack capture pipeline. */
int setup_stack_capture_event(int freq, bpf_event_process_fn fn, struct stack_capture_ctx *user_ctx);

/*
 * The kernel stack of a lite-object sample (stack_event::kstack_id) into
 * @kstack, at most @max_level entries; returns how many, 0 if none.
 */
int stack_capture_lookup_kstack(long kstack_id, unsigned long *kstack, int max_level);

/**
 * struct offcpu_capture_ctx - userspace context for off-CPU capture setup
 * @pid: pid/tgid filter, or 0 for all tasks
 * @comm: task comm filter, zero-terminated when present
 */
struct offcpu_capture_ctx {
	int pid;
	char comm[TASK_COMM_LEN];
	/* sample target_ctl's target set; @pid and @comm are then unused */
	bool target_dynamic;
};

/* Clamp the copied user-stack payload for off-CPU capture. */
int set_offcpu_capture_size(int size);

/* Create the off-CPU capture pipeline. */
int setup_offcpu_capture_event(int freq, bpf_event_process_fn fn, struct offcpu_capture_ctx *user_ctx);

/* Like stack_capture_lookup_kstack(), for off-CPU samples. */
int offcpu_capture_lookup_kstack(long kstack_id, unsigned long *kstack, int max_level);

/*
 * Dynamic target selection: before the capture module is initialised, name
 * target_ctl's target_pids fd to share (@dynamic false: keep a one-entry
 * private copy).  After init, the fd each object really uses, to prove the
 * map is shared, and stack_capture's t0 program for target_ctl's exec hook.
 */
void stack_capture_set_target(int owner_fd, bool dynamic);
int stack_capture_target_pids_fd(void);
int stack_capture_t0_prog_fd(void);
void offcpu_capture_set_target(int owner_fd, bool dynamic);
int offcpu_capture_target_pids_fd(void);

/* Subscribe to process-exit notifications used for pid-context retirement. */
int setup_process_exit_event(bpf_event_process_fn fn);

#endif /* CPA_BPF_H */
