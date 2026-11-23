// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CPA_UNWIND_QUEUE_H
#define CPA_UNWIND_QUEUE_H

#include "cpa_stack_sample.h"
#include "cpa_unwinder.h"

#include <stdbool.h>
#include <stdint.h>

/**
 * @file cpa_unwind_queue.h
 * @brief Samples and process exits on their way to the unwind workers.
 *
 * The queue is split into one lane per unwind worker (--unwind_workers).  A
 * process (tgid) belongs to one lane for the whole session: its samples and
 * its exit go there, so the per-process unwinder state behind them has one
 * writer, and an exit still finds the samples of its instance in flight.
 */

#define CPA_PID_EXIT_DRAIN_BATCH 256
/* Upper bound of --unwind_workers, hence of the lanes. */
#define CPA_UNWIND_LANES_MAX 64

/* Index 0 has two roles, each named where it is used: */
/* the worker on the runtime loop of the main thread (cpa_runtime_loop) */
#define CPA_MAIN_WORKER 0
/* the context that loads the kernel symbols every worker looks up */
#define CPA_KERNEL_SYMBOLS_CTX 0

/* Most --unwind_workers allowed here: the online CPUs, at most 64. */
unsigned int cpa_unwind_workers_max(void);
/*
 * Parse an --unwind_workers value: decimal digits only, 1..@max.  Returns 0,
 * -EINVAL (not a number) or -ERANGE.
 */
int cpa_unwind_workers_parse(const char *value, unsigned int max, unsigned int *workers_out);

int cpa_unwind_queue_init(int queue_size, unsigned int lanes);
/* Drop what is queued; with @destroy also free the rings and the sample pool. */
void cpa_unwind_queue_cleanup(bool destroy);
void cpa_unwind_queue_set_accepting(bool accepting);
bool cpa_unwind_queue_accepting(void);

/* Lanes of this session (1 before init); the lane of a process. */
unsigned int cpa_unwind_queue_lanes(void);
unsigned int cpa_unwind_lane_of(uint32_t tgid);

/*
 * Sleep until @lane has work or @deadline_ns (CLOCK_MONOTONIC, 0 = none)
 * passes; returns its next sample, if any.
 */
struct stack_sample *cpa_unwind_queue_wait_sample(unsigned int lane, uint64_t deadline_ns);
struct stack_sample *cpa_unwind_queue_pop_sample(unsigned int lane);
/*
 * A popped sample is done (unwound or not): its admission credit and
 * pending count go back, an exit waiting on it may be released, and it is
 * freed.  The only way a popped sample leaves the worker.
 */
void cpa_unwind_queue_retire_sample(struct stack_sample *sample);

/*
 * Exits of @lane ready to be reaped: past their grace period and with no
 * sample of the instance in flight.  *next_deadline_ns is when the next one
 * may be, 0 if none is queued.
 */
unsigned int cpa_unwind_queue_pop_ready_exits(unsigned int lane, struct exit_event **out, unsigned int max_events,
					      uint64_t *next_deadline_ns);

/* Samples queued in all lanes. */
unsigned int cpa_unwind_queue_sample_len(void);
/*
 * Samples holding an admission credit, all lanes: queued or being unwound.
 * At most queue_size - 1 + lanes; the drop policy's pressure.
 */
unsigned int cpa_unwind_queue_admitted(void);
/* Samples accepted but not finished, all lanes.  Takes every lane lock. */
unsigned int cpa_unwind_queue_pending_samples(void);
/* Exits queued in all lanes. */
unsigned int cpa_unwind_queue_exit_len(void);

/* Wake every lane's worker (stop, restart); async-signal-safe. */
void cpa_unwind_queue_kick(void);

#endif /* CPA_UNWIND_QUEUE_H */
