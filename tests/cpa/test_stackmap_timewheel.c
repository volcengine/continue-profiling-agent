// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: ByteDance Inc

#include "stackmap_timewheel.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

struct flushed_bucket {
	uint64_t start_ms;
	uint64_t end_ms;
	uint64_t ids1;
	uint64_t ids2;
};

struct flush_ctx {
	struct flushed_bucket buckets[8];
	size_t len;
};

static int collect_flush(uint64_t start_ms, uint64_t end_ms,
			 struct stackmap_count_table *counts, void *arg)
{
	struct flush_ctx *ctx = arg;
	struct flushed_bucket *bucket;
	uint64_t count = 0;

	assert(ctx->len < sizeof(ctx->buckets) / sizeof(ctx->buckets[0]));
	bucket = &ctx->buckets[ctx->len++];
	bucket->start_ms = start_ms;
	bucket->end_ms = end_ms;

	if (stackmap_count_table_get(counts, 1, &count))
		bucket->ids1 = count;
	if (stackmap_count_table_get(counts, 2, &count))
		bucket->ids2 = count;
	return 0;
}

int main(void)
{
	struct stackmap_timewheel *wheel;
	struct stackmap_timewheel_stats stats = { 0 };
	struct flush_ctx ctx = { 0 };

	wheel = stackmap_timewheel_create(10000);
	assert(wheel);

	assert(stackmap_timewheel_add(wheel, 1000, 1, 3) == 0);
	assert(stackmap_timewheel_add(wheel, 2000, 2, 4) == 0);
	assert(stackmap_timewheel_flush_ready(wheel, 11000, collect_flush,
					      &ctx) == 0);
	assert(ctx.len == 0);

	assert(stackmap_timewheel_flush_ready(wheel, 12000, collect_flush,
					      &ctx) == 0);
	assert(ctx.len == 1);
	assert(ctx.buckets[0].start_ms == 1000);
	assert(ctx.buckets[0].end_ms == 2000);
	assert(ctx.buckets[0].ids1 == 3);
	assert(ctx.buckets[0].ids2 == 0);

	assert(stackmap_timewheel_add(wheel, 1500, 1, 5) == 0);
	assert(stackmap_timewheel_add(wheel, 2500, 2, 7) == 0);
	assert(stackmap_timewheel_get_stats(wheel, &stats) == 0);
	assert(stats.clamped_late_count == 5);

	assert(stackmap_timewheel_flush_ready(wheel, 13000, collect_flush,
					      &ctx) == 0);
	assert(ctx.len == 2);
	assert(ctx.buckets[1].start_ms == 2000);
	assert(ctx.buckets[1].end_ms == 3000);
	assert(ctx.buckets[1].ids1 == 5);
	assert(ctx.buckets[1].ids2 == 11);

	assert(stackmap_timewheel_add(wheel, 4000, 1, 9) == 0);
	assert(stackmap_timewheel_flush_all(wheel, collect_flush, &ctx) == 0);
	assert(ctx.len == 3);
	assert(ctx.buckets[2].start_ms == 4000);
	assert(ctx.buckets[2].end_ms == 5000);
	assert(ctx.buckets[2].ids1 == 9);
	assert(ctx.buckets[2].ids2 == 0);

	assert(stackmap_timewheel_get_stats(wheel, &stats) == 0);
	assert(stats.pending_bucket_count == 0);
	assert(stats.pending_count_total == 0);
	assert(stats.flushed_bucket_count == 3);

	stackmap_timewheel_destroy(wheel);
	return 0;
}
