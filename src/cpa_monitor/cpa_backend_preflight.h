// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CPA_BACKEND_PREFLIGHT_H
#define CPA_BACKEND_PREFLIGHT_H

/**
 * @file cpa_backend_preflight.h
 * @brief Backend capability checks and fallback policy for `cpa monitor`.
 */

/**
 * cpa_monitor_prepare_backend - validate backend requirements before runtime start
 * @ctx: parsed CLI context for `cpa monitor`
 *
 * This helper validates the requested monitor mode against the currently
 * available BPF and perf capabilities. It may rewrite `backend` from `bpf`
 * to `perf` when the request is eligible for fallback.
 *
 * Return: 0 on success, negative errno-style value on rejection.
 */
int cpa_monitor_prepare_backend(void *ctx);

#endif /* CPA_BACKEND_PREFLIGHT_H */
