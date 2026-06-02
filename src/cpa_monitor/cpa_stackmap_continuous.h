// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CPA_STACKMAP_CONTINUOUS_H
#define CPA_STACKMAP_CONTINUOUS_H

#include "cli_dir_manager.h"
#include "cpa_runtime.h"

/**
 * @file cpa_stackmap_continuous.h
 * @brief Stackmap continuity helper used by periodic dump modes.
 */

/**
 * cpa_get_stackmap_save_dir - return the active stackmap dump directory
 *
 * Return: directory descriptor used by continuous stackmap dumping.
 */
struct dir_info *cpa_get_stackmap_save_dir(void);

/**
 * cpa_stackmap_continuous_prepare_restart - flush current delta and stage next store
 *
 * This runs after capture/unwind workers have been paused and before the
 * runtime attempts to allocate the next shared tracemap. The active store
 * directory is not changed until the restart is committed.
 */
int cpa_stackmap_continuous_prepare_restart(void);

/**
 * cpa_stackmap_continuous_commit_restart - rotate continuous store after restart allocation
 *
 * This commits the next store directory only after the replacement tracemap is
 * ready, so a failed restart keeps using the previous directory unchanged.
 *
 * Return: 0 on success, negative value on failure.
 */
int cpa_stackmap_continuous_commit_restart(void);

/**
 * cpa_stackmap_continuous_abort_restart - discard a staged store rotation
 *
 * A failed restart keeps the current active store directory and removes the
 * unused staged directory.
 */
void cpa_stackmap_continuous_abort_restart(void);

#endif /* CPA_STACKMAP_CONTINUOUS_H */
