// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: ByteDance Inc

#ifndef __STACKMAP_TIMEWHEEL_H__
#define __STACKMAP_TIMEWHEEL_H__

#include "stackmap_count_table.h"

#include <stddef.h>
#include <stdint.h>

struct stackmap_timewheel;

struct stackmap_timewheel_stats {
	size_t pending_bucket_count;
	uint64_t pending_count_total;
	uint64_t clamped_late_count;
	uint64_t flushed_bucket_count;
};

typedef int (*stackmap_timewheel_flush_fn)(
	uint64_t start_ms, uint64_t end_ms,
	struct stackmap_count_table *counts, void *ctx);

struct stackmap_timewheel *stackmap_timewheel_create(uint64_t hold_ms);
void stackmap_timewheel_destroy(struct stackmap_timewheel *wheel);

int stackmap_timewheel_add(struct stackmap_timewheel *wheel,
			   uint64_t record_ms, uint32_t ids_id,
			   uint64_t count);
int stackmap_timewheel_flush_ready(struct stackmap_timewheel *wheel,
				   uint64_t now_record_ms,
				   stackmap_timewheel_flush_fn flush_fn,
				   void *ctx);
int stackmap_timewheel_flush_all(struct stackmap_timewheel *wheel,
				 stackmap_timewheel_flush_fn flush_fn,
				 void *ctx);
void stackmap_timewheel_reset(struct stackmap_timewheel *wheel);
int stackmap_timewheel_get_stats(const struct stackmap_timewheel *wheel,
				 struct stackmap_timewheel_stats *stats);

#endif
