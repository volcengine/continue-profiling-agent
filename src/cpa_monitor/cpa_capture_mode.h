// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CPA_CAPTURE_MODE_H
#define CPA_CAPTURE_MODE_H

#include <stdbool.h>

/**
 * @file cpa_capture_mode.h
 * @brief Helpers for deriving CPA monitor fast paths from parsed CLI options.
 */

/**
 * cpa_kernel_only_fastpath_requested - return true when the request can bypass
 * libgunwinder and process-exit tracking.
 * @cli_ctx: parsed monitor CLI context
 *
 * Return: true for BPF on-CPU kernel-only capture requests.
 */
bool cpa_kernel_only_fastpath_requested(void *cli_ctx);

#endif /* CPA_CAPTURE_MODE_H */
