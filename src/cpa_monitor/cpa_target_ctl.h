// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CPA_TARGET_CTL_H
#define CPA_TARGET_CTL_H

#include <stdbool.h>
#include <stdint.h>

#include "cpa_target.h"

/**
 * @file cpa_target_ctl.h
 * @brief Userspace side of process selection (see cpa_target_ctl.c).
 *
 * Call order for a BPF session: cpa_target_configure() when the options
 * are read; for a dynamic selection INIT_MODULE_BPF(target_ctl), then
 * cpa_target_prepare() before the capture module is initialised, then
 * cpa_target_start() once it is; cpa_target_shutdown() when it stops.
 */

/* Parse the selection options; -EINVAL with a message on a bad selection. */
int cpa_target_configure(void *cli_ctx);

/* True when the selection goes through target_ctl's target set. */
bool cpa_target_is_dynamic(void);

/* Exit capture's own selection; before cpa_target_prepare(). */
void cpa_target_set_exit(const struct cpa_exit_spec *exit);

/* True when target_ctl must be loaded: a dynamic selection, or exec and fork
 * notifications for --exit_comm's env condition. */
bool cpa_target_needs_bpf(void);

const struct cpa_target_spec *cpa_target_spec(void);

/* Publish the rules and tell the capture modules which map to share. */
int cpa_target_prepare(void);

/* Check the map is shared, attach the birth hooks, seed the target set. */
int cpa_target_start(bool oncpu, bool offcpu);

void cpa_target_shutdown(void);

/* An exit the unwinder has reaped: drop its instance if no thread lives. */
void cpa_target_on_exit(uint32_t pid);

/*
 * Refuse a profiler running in a shifted time namespace: process start
 * times read from /proc include its offsets, BPF sees the host clocks, so
 * no process instance would match.  0 when the host namespace is used.
 */
int cpa_check_time_namespace(void);

#endif
