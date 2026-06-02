// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

/**
 * @file btf_helpers.h
 * @brief Helpers for selecting and managing BTF used by CO-RE programs.
 */

#ifndef CPA_BPF_BTF_HELPERS_H
#define CPA_BPF_BTF_HELPERS_H

#include <bpf/libbpf.h>

#define FIELD_LEN 65

/**
 * @brief Basic OS information used for selecting prebuilt BTF artifacts.
 */
struct os_info {
	char id[FIELD_LEN];
	char version[FIELD_LEN];
	char arch[FIELD_LEN];
	char kernel_release[FIELD_LEN];
};

/**
 * @brief Get OS information for the current runtime.
 *
 * @return Pointer to an internal os_info instance, or NULL on failure.
 */
struct os_info *get_os_info();

/**
 * @brief Ensure a BTF file is available for CO-RE and configure @p opts accordingly.
 *
 * @param opts libbpf object open options to be updated.
 * @return 0 on success; negative value on failure.
 */
int ensure_core_btf(struct bpf_object_open_opts *opts);

/**
 * @brief Cleanup resources allocated by ensure_core_btf().
 *
 * @param opts libbpf object open options previously passed to ensure_core_btf().
 */
void cleanup_core_btf(struct bpf_object_open_opts *opts);

#endif
