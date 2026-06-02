// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef __CPA_RUNTIME_H__
#define __CPA_RUNTIME_H__

#include "cli_stackmap.h"

/**
 * @file cpa_runtime.h
 * @brief Runtime worker abstraction used by CPA modules.
 */

/**
 * enum cpa_worker_init_result - worker initialization result codes
 */
enum cpa_worker_init_result {
	CPA_INIT_SUCCESS = 0,
	CPA_INIT_FAILED = 1,
	CPA_INIT_SKIP = 2,
};

/**
 * Worker lifecycle callback signatures.
 */
typedef void (*cpa_worker_timer_fn)(void *worker_ctx);
typedef void (*cpa_worker_main_worker_fn)(void *worker_ctx);
typedef enum cpa_worker_init_result (*cpa_worker_init_fn)(void *cli_ctx, void *worker_ctx);
typedef void (*cpa_worker_destroy_fn)(void *worker_ctx);
typedef void (*cpa_worker_pause_fn)(void *worker_ctx);
typedef void (*cpa_worker_restore_fn)(void *worker_ctx);

#define CPA_WORKER_INDEX_NOCARE (0xFFFF)

/**
 * struct cpa_worker - runtime worker registration entry
 * @worker_name: stable worker name used for logging and diagnostics
 * @worker_ctx: worker-private context pointer managed by the worker itself
 * @worker_index: startup ordering key, smaller values start earlier
 * @init_fn: optional worker initialization hook
 * @destroy_fn: optional worker teardown hook
 * @pause_fn: optional hook used when runtime pauses workers
 * @restore_fn: optional hook used when runtime resumes workers
 * @timer_fn: optional periodic callback
 * @main_worker_fn: optional main-loop callback
 */
struct cpa_worker {
	char worker_name[32];
	void *worker_ctx;
	unsigned int worker_index;

	cpa_worker_init_fn init_fn;
	cpa_worker_destroy_fn destroy_fn;

	cpa_worker_pause_fn pause_fn;
	cpa_worker_restore_fn restore_fn;

	cpa_worker_timer_fn timer_fn;
	cpa_worker_main_worker_fn main_worker_fn;
};

/**
 * cpa_runtime_register - register workers into the global runtime scheduler
 * @to_register: array of worker pointers to register
 * @count: number of worker entries in @to_register
 *
 * Return: 0 on success, negative value on failure.
 */
int cpa_runtime_register(struct cpa_worker **to_register, int count);

/**
 * cpa_runtime_start - initialize runtime with parsed CLI context
 * @cli_ctx: parsed CLI context shared across workers
 *
 * Return: 0 on success, negative value on failure.
 */
int cpa_runtime_start(void *cli_ctx);

/**
 * cpa_runtime_loop - enter the runtime main loop
 */
void cpa_runtime_loop(void);

/**
 * cpa_runtime_stop - stop the runtime and background threads
 *
 * Return: 0 on success, negative value on failure.
 */
int cpa_runtime_stop(void);

/**
 * cpa_main_tracemap_get_and_lock - acquire the shared tracemap with its lock held
 *
 * Return: locked tracemap pointer for direct producer writes.
 */
struct cli_stackmap *cpa_main_tracemap_get_and_lock(void);

/**
 * cpa_main_tracemap_unlock - release the tracemap lock acquired above
 */
void cpa_main_tracemap_unlock(void);

/**
 * cpa_runtime_need_restart - request the runtime restart flow
 */
void cpa_runtime_need_restart(void);

#endif /* __CPA_RUNTIME_H__ */
