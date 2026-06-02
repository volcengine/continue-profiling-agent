// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

/**
 * @file core.h
 * @brief Internal core helpers shared by CPA user space BPF modules.
 */
#ifndef CPA_BPF_CORE_H
#define CPA_BPF_CORE_H

#include <stdbool.h>
#include <stdio.h>

#include <linux/types.h>

#include <bpf/libbpf.h>

extern bool __cpa_bpf_verbose;

/**
 * Logging helpers for BPF back-end modules.
 */
#define BPF_INFO(fmt, ...)                                                                                                                                                                                                                                     \
	do {                                                                                                                                                                                                                                                   \
		if (__cpa_bpf_verbose)                                                                                                                                                                                                                         \
			printf("[BPF][INFO] " fmt, ##__VA_ARGS__);                                                                                                                                                                                             \
	} while (0)

#define BPF_WARN(fmt, ...) fprintf(stderr, "[BPF][WARN] " fmt, ##__VA_ARGS__)
#define BPF_ERR(fmt, ...) fprintf(stderr, "[BPF][ERR] " fmt, ##__VA_ARGS__)

#define BPF_INFOE(fmt, ...)                                                                                                                                                                                                                                    \
	do {                                                                                                                                                                                                                                                   \
		if (__cpa_bpf_verbose)                                                                                                                                                                                                                         \
			fprintf(stderr, "[BPF][INFO] " fmt, ##__VA_ARGS__);                                                                                                                                                                                    \
	} while (0)

/**
 * Per-module constructor-like hooks exported by generated skeleton modules.
 */
struct bpf_module_ops {
	int (*init_bpf_module)(const struct bpf_object_open_opts *optsp);
	void (*exit_bpf_module)(void);
	const char *kernel_version;
};

/*
 * BPF_MODULE() wires the per-module open/close callbacks into the shared
 * module table and records the minimum supported kernel version.
 */
#define BPF_MODULE(name, version)                                                                                                                                                                                                                              \
	const struct bpf_module_ops bpf_module_##name = {                                                                                                                                                                                                      \
		.init_bpf_module = init_bpf_module,                                                                                                                                                                                                            \
		.exit_bpf_module = exit_bpf_module,                                                                                                                                                                                                            \
		.kernel_version = version,                                                                                                                                                                                                                     \
	}

__u32 get_kernel_version(void);
__u32 get_module_version(const char *name, const char *version);

/**
 * Convert version tuple to comparable integer.
 */
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + ((c) > 255 ? 255 : (c)))

#endif
