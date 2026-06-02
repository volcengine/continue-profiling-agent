// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: ByteDance Inc

#include "stackmap_timewheel.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define STACKMAP_TIMEWHEEL_BUCKET_MS 1000ULL
#define STACKMAP_TIMEWHEEL_DEFAULT_HOLD_MS 10000ULL
#define STACKMAP_TIMEWHEEL_INITIAL_BUCKETS 16U

struct stackmap_timewheel_bucket {
	uint64_t sec;
	struct stackmap_count_table *counts;
	uint64_t count_total;
};

struct stackmap_timewheel {
	struct stackmap_timewheel_bucket *buckets;
	size_t bucket_count;
	size_t bucket_cap;
	uint64_t hold_sec;
	uint64_t max_seen_record_ms;
	uint64_t oldest_open_sec;
	bool has_oldest_open_sec;
	uint64_t clamped_late_count;
	uint64_t flushed_bucket_count;
};

static uint64_t hold_ms_to_sec(uint64_t hold_ms)
{
	if (hold_ms == 0)
		hold_ms = STACKMAP_TIMEWHEEL_DEFAULT_HOLD_MS;
	return (hold_ms + STACKMAP_TIMEWHEEL_BUCKET_MS - 1) / STACKMAP_TIMEWHEEL_BUCKET_MS;
}

static uint64_t record_ms_to_sec(uint64_t record_ms)
{
	/* Buckets are fixed one-second slots. */
	return record_ms / STACKMAP_TIMEWHEEL_BUCKET_MS;
}

static uint64_t sec_to_start_ms(uint64_t sec)
{
	return sec * STACKMAP_TIMEWHEEL_BUCKET_MS;
}

static int ensure_bucket_capacity(struct stackmap_timewheel *wheel)
{
	struct stackmap_timewheel_bucket *next;
	size_t next_cap;

	if (wheel->bucket_count < wheel->bucket_cap)
		return 0;

	next_cap = wheel->bucket_cap ? wheel->bucket_cap * 2 : STACKMAP_TIMEWHEEL_INITIAL_BUCKETS;
	next = realloc(wheel->buckets, next_cap * sizeof(*next));
	if (!next)
		return -1;

	memset(next + wheel->bucket_cap, 0, (next_cap - wheel->bucket_cap) * sizeof(*next));
	wheel->buckets = next;
	wheel->bucket_cap = next_cap;
	return 0;
}

static struct stackmap_timewheel_bucket *find_bucket(struct stackmap_timewheel *wheel, uint64_t sec)
{
	for (size_t i = 0; i < wheel->bucket_count; i++) {
		if (wheel->buckets[i].sec == sec)
			return &wheel->buckets[i];
	}
	return NULL;
}

static struct stackmap_timewheel_bucket *get_or_create_bucket(struct stackmap_timewheel *wheel, uint64_t sec)
{
	struct stackmap_timewheel_bucket *bucket;

	bucket = find_bucket(wheel, sec);
	if (bucket)
		return bucket;

	if (ensure_bucket_capacity(wheel) != 0)
		return NULL;

	bucket = &wheel->buckets[wheel->bucket_count++];
	bucket->sec = sec;
	bucket->counts = stackmap_count_table_create();
	bucket->count_total = 0;
	if (!bucket->counts) {
		wheel->bucket_count--;
		return NULL;
	}
	return bucket;
}

static void destroy_bucket(struct stackmap_timewheel_bucket *bucket)
{
	stackmap_count_table_destroy(bucket->counts);
	bucket->counts = NULL;
	bucket->count_total = 0;
	bucket->sec = 0;
}

static void remove_bucket_at(struct stackmap_timewheel *wheel, size_t index)
{
	destroy_bucket(&wheel->buckets[index]);
	if (index + 1 < wheel->bucket_count) {
		memmove(&wheel->buckets[index], &wheel->buckets[index + 1], (wheel->bucket_count - index - 1) * sizeof(*wheel->buckets));
	}
	wheel->bucket_count--;
	memset(&wheel->buckets[wheel->bucket_count], 0, sizeof(*wheel->buckets));
}

static bool find_oldest_bucket(const struct stackmap_timewheel *wheel, bool (*predicate)(const struct stackmap_timewheel *, const struct stackmap_timewheel_bucket *, void *), void *arg, size_t *index)
{
	bool found = false;
	uint64_t best_sec = 0;

	for (size_t i = 0; i < wheel->bucket_count; i++) {
		const struct stackmap_timewheel_bucket *bucket = &wheel->buckets[i];

		if (!predicate(wheel, bucket, arg))
			continue;
		if (!found || bucket->sec < best_sec) {
			found = true;
			best_sec = bucket->sec;
			*index = i;
		}
	}
	return found;
}

struct flush_before_arg {
	uint64_t watermark_sec;
};

static bool bucket_before_watermark(const struct stackmap_timewheel *wheel, const struct stackmap_timewheel_bucket *bucket, void *arg)
{
	struct flush_before_arg *flush_arg = arg;

	(void)wheel;
	return bucket->sec < flush_arg->watermark_sec;
}

static bool any_bucket(const struct stackmap_timewheel *wheel, const struct stackmap_timewheel_bucket *bucket, void *arg)
{
	(void)wheel;
	(void)bucket;
	(void)arg;
	return true;
}

static int flush_bucket_at(struct stackmap_timewheel *wheel, size_t index, stackmap_timewheel_flush_fn flush_fn, void *ctx)
{
	struct stackmap_timewheel_bucket *bucket = &wheel->buckets[index];
	uint64_t start_ms = sec_to_start_ms(bucket->sec);
	uint64_t end_ms = start_ms + STACKMAP_TIMEWHEEL_BUCKET_MS;

	/* Emit [start_ms, start_ms + 1000ms), then remove the bucket. */
	if (flush_fn && flush_fn(start_ms, end_ms, bucket->counts, ctx) != 0)
		return -1;

	wheel->flushed_bucket_count++;
	remove_bucket_at(wheel, index);
	return 0;
}

struct stackmap_timewheel *stackmap_timewheel_create(uint64_t hold_ms)
{
	struct stackmap_timewheel *wheel = calloc(1, sizeof(*wheel));

	if (!wheel)
		return NULL;

	wheel->hold_sec = hold_ms_to_sec(hold_ms);
	wheel->bucket_cap = STACKMAP_TIMEWHEEL_INITIAL_BUCKETS;
	wheel->buckets = calloc(wheel->bucket_cap, sizeof(*wheel->buckets));
	if (!wheel->buckets) {
		free(wheel);
		return NULL;
	}
	return wheel;
}

void stackmap_timewheel_destroy(struct stackmap_timewheel *wheel)
{
	if (!wheel)
		return;

	stackmap_timewheel_reset(wheel);
	free(wheel->buckets);
	free(wheel);
}

int stackmap_timewheel_add(struct stackmap_timewheel *wheel, uint64_t record_ms, uint32_t ids_id, uint64_t count)
{
	struct stackmap_timewheel_bucket *bucket;
	uint64_t sec;

	if (!wheel)
		return -1;

	if (record_ms > wheel->max_seen_record_ms)
		wheel->max_seen_record_ms = record_ms;

	sec = record_ms_to_sec(record_ms);
	if (wheel->has_oldest_open_sec && sec < wheel->oldest_open_sec) {
		/* Late events are clamped into the oldest still-open bucket. */
		sec = wheel->oldest_open_sec;
		wheel->clamped_late_count += count;
	}

	bucket = get_or_create_bucket(wheel, sec);
	if (!bucket)
		return -1;
	if (stackmap_count_table_add(bucket->counts, ids_id, count) != 0)
		return -1;

	bucket->count_total += count;
	return 0;
}

int stackmap_timewheel_flush_ready(struct stackmap_timewheel *wheel, uint64_t now_record_ms, stackmap_timewheel_flush_fn flush_fn, void *ctx)
{
	struct flush_before_arg arg = { 0 };
	uint64_t effective_ms;
	uint64_t effective_sec;
	size_t index = 0;

	if (!wheel)
		return -1;

	effective_ms = wheel->max_seen_record_ms > now_record_ms ? wheel->max_seen_record_ms : now_record_ms;
	effective_sec = record_ms_to_sec(effective_ms);
	arg.watermark_sec = effective_sec > wheel->hold_sec ? effective_sec - wheel->hold_sec : 0;

	/* Flush only buckets older than the hold window watermark. */
	wheel->oldest_open_sec = arg.watermark_sec;
	wheel->has_oldest_open_sec = true;

	while (find_oldest_bucket(wheel, bucket_before_watermark, &arg, &index)) {
		if (flush_bucket_at(wheel, index, flush_fn, ctx) != 0)
			return -1;
	}
	return 0;
}

int stackmap_timewheel_flush_all(struct stackmap_timewheel *wheel, stackmap_timewheel_flush_fn flush_fn, void *ctx)
{
	size_t index = 0;

	if (!wheel)
		return -1;

	while (find_oldest_bucket(wheel, any_bucket, NULL, &index)) {
		if (flush_bucket_at(wheel, index, flush_fn, ctx) != 0)
			return -1;
	}
	return 0;
}

void stackmap_timewheel_reset(struct stackmap_timewheel *wheel)
{
	if (!wheel)
		return;

	for (size_t i = 0; i < wheel->bucket_count; i++)
		destroy_bucket(&wheel->buckets[i]);

	wheel->bucket_count = 0;
	wheel->max_seen_record_ms = 0;
	wheel->oldest_open_sec = 0;
	wheel->has_oldest_open_sec = false;
}

int stackmap_timewheel_get_stats(const struct stackmap_timewheel *wheel, struct stackmap_timewheel_stats *stats)
{
	if (!wheel || !stats)
		return -1;

	memset(stats, 0, sizeof(*stats));
	stats->pending_bucket_count = wheel->bucket_count;
	stats->clamped_late_count = wheel->clamped_late_count;
	stats->flushed_bucket_count = wheel->flushed_bucket_count;
	for (size_t i = 0; i < wheel->bucket_count; i++)
		stats->pending_count_total += wheel->buckets[i].count_total;
	return 0;
}
