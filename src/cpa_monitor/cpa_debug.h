// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CPA_DEBUG_H
#define CPA_DEBUG_H

#include "cpa_unwinder.h"

/**
 * @file cpa_debug.h
 * @brief Debug dump helpers for stack sample inspection.
 */

/**
 * cpa_debug_dump_sample - dump one decoded sample for offline inspection
 * @sample: sample queued to the unwinder
 *
 * The dump is only emitted when debug dumping is enabled for the target pid.
 */
void cpa_debug_dump_sample(struct stack_sample *sample);

#endif /* CPA_DEBUG_H */
