// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef __CPA_PAGEFAULT_TRACKER_H__
#define __CPA_PAGEFAULT_TRACKER_H__

#include <stdbool.h>
#include <stdint.h>

/*
 * Live set of sampled anonymous pages of one process, and the resident
 * bytes it adds up to per allocating stack.
 *
 * A record is an address range -- a sampled page, a THP or what is left of
 * one -- with the bytes it stands for and the stack that faulted it in.
 * Every input carries the time it happened:
 *
 *   - Address-space events (release, move, reset) are applied in time
 *     order.  They are queued and applied once older than the flush bound
 *     the caller gives, which covers the reordering of per-CPU buffers.
 *     Applied, they are logged.
 *   - An allocation arrives when its stack has been unwound, possibly after
 *     events that are newer than it.  It is replayed through the logged
 *     events newer than it, so it ends up where those left it: released,
 *     moved, or kept.  One newer than a queued event waits behind it in
 *     the queue: the range it lands in may still hold records that event
 *     takes away (munmap, mmap of the same addresses, a fault).
 *
 * An event only affects records that were at its range before it (a record
 * remembers since when it is where it is).  Pages that became live again
 * after a release keep the first stack seen for them.
 *
 * Not thread safe: the caller serializes.
 */
struct pf_tracker;

enum pf_event_kind {
	PF_EV_RELEASE = 1,	/* [start, end) no longer backed */
	PF_EV_MOVE = 2,		/* [start, end) now at new_start */
	PF_EV_RESET = 3,	/* the address space is gone */
};

enum pf_alloc_result {
	PF_ALLOC_ADDED,
	PF_ALLOC_DUPLICATE,	/* the range is already live: swap-in, copy on write */
	PF_ALLOC_LATE,		/* released (or reset) after it was allocated */
	PF_ALLOC_QUEUED,	/* placed in time order at a flush */
};

struct pf_tracker_stats {
	uint64_t records;
	uint64_t stacks;
	uint64_t resident_bytes;
	uint64_t added;
	uint64_t duplicates;
	uint64_t late;
	uint64_t released_bytes;
	uint64_t moved;
	uint64_t resets;
	/* inputs the tracker could not place exactly */
	uint64_t late_unknown;	/* allocations older than the log reaches back */
	uint64_t out_of_order;	/* events older than an earlier flush bound */
	uint64_t failed;	/* out of memory */
};

struct pf_tracker *pf_tracker_new(void);
void pf_tracker_free(struct pf_tracker *t);

/* A page of @pages pages at @addr standing for @bytes, faulted in at @ts. */
enum pf_alloc_result pf_tracker_alloc(struct pf_tracker *t, uint64_t ts,
				      uint64_t addr, uint32_t pages,
				      uint64_t bytes, uint32_t stack);

/* Queue an address-space event of @ts (@new_start: moves only). */
void pf_tracker_submit(struct pf_tracker *t, enum pf_event_kind kind,
		       uint64_t ts, uint64_t start, uint64_t end,
		       uint64_t new_start);

/*
 * Apply the queued events older than @bound, in time order.  Events
 * submitted later with a time below @bound are applied at once and
 * counted as out of order.
 */
void pf_tracker_flush(struct pf_tracker *t, uint64_t bound);

/* Forget everything: the stack ids behind the records are gone. */
void pf_tracker_clear(struct pf_tracker *t);

/* Every stack with resident bytes, in no particular order. */
void pf_tracker_for_each_stack(struct pf_tracker *t,
			       void (*fn)(uint32_t stack, uint64_t bytes, void *ctx),
			       void *ctx);

void pf_tracker_get_stats(const struct pf_tracker *t, struct pf_tracker_stats *out);

#endif
