// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef __CLI_STACKMAP_PRIVATE_H__
#define __CLI_STACKMAP_PRIVATE_H__

#include <pthread.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <uthash.h>
#include <unistd.h>

#include <cli_zstd_helper.h>
#include "stackmap_count_table.h"
#include "stackmap_timewheel.h"

/**
 * @file cli_stackmap_private.h
 * @brief Internal stackmap storage structures used by shared aggregator helpers.
 */

/**
 * struct str_hash - interned frame string table entry.
 * @str: owning frame string.
 * @id: stable frame id.
 * @hh: uthash linkage.
 */
struct str_hash {
	char *str;
	uint32_t id;
	UT_hash_handle hh;
};

/**
 * struct ids_hash - interned stack id list.
 * @ids: ordered frame-id list for one stack.
 * @ids_len: number of frame ids.
 * @id: stable ids-hash identifier.
 * @hh: uthash linkage.
 */
struct ids_hash {
	uint32_t *ids;
	uint32_t ids_len;
	uint32_t id;
	UT_hash_handle hh;
};

/**
 * struct id_count - aggregate count for one ids list.
 * @ids_id: ids id reference.
 * @count: sample occurrence count.
 * @hh: uthash linkage.
 */
struct id_count {
	uint32_t ids_id;
	uint64_t count;
	UT_hash_handle hh;
};

/**
 * struct cli_stackmap_entry - mutable list of frame ids for one stack.
 * @ids: frame-id array.
 * @ids_maxlen: allocated capacity of @ids.
 * @last_reverse: reverse cursor index for flamegraph output.
 * @ids_len: number of valid frame ids in @ids.
 */
struct cli_stackmap_entry {
	uint32_t *ids;
	uint32_t ids_maxlen;
	uint32_t last_reverse;
	uint32_t ids_len;
};

struct cli_stackmap_memory_usage;

/**
 * struct cli_stackmap - mutable stack aggregation container.
 * @current: in-progress stack entry being built.
 * @str_id: next frame string id to allocate.
 * @str_hash: hash table of interned strings by id.
 * @str_hash_by_id: array index for id to string entry mapping.
 * @str_hash_maxlen: allocated size of @str_hash_by_id.
 * @dumped_str_id: last dumped string id.
 * @ids_id: next ids id to allocate.
 * @ids_hash: hash table of interned ids arrays.
 * @ids_hash_by_id: array index for id to ids entry mapping.
 * @ids_hash_maxlen: allocated size of @ids_hash_by_id.
 * @dumped_ids_id: last dumped ids id.
 * @idsmap: output stream for ids data.
 * @strmap: output stream for string data.
 * @stackmap: output stream for folded stack data.
 * @usage: memory usage accumulator.
 * @record_start_time: timestamp for current dump interval.
 * @day_start: timestamp for local day boundary.
 * @count_table: empty scratch table used for timewheel sentinel records.
 * @timewheel: optional delayed stack count buckets.
 * @id_count: aggregated output list.
 * @id_count_lock: lock protecting @id_count.
 * @strmap_lock: lock protecting string map state.
 * @idsmap_lock: lock protecting ids map state.
 */
struct cli_stackmap {
	struct cli_stackmap_entry *current;

	uint32_t str_id;
	struct str_hash *str_hash;
	struct str_hash **str_hash_by_id;
	uint32_t str_hash_maxlen;
	uint32_t dumped_str_id;

	uint32_t ids_id;
	struct ids_hash *ids_hash;
	struct ids_hash **ids_hash_by_id;
	uint32_t ids_hash_maxlen;
	uint32_t dumped_ids_id;

	ZSTDStream *idsmap;
	ZSTDStream *strmap;
	ZSTDStream *stackmap;

	struct cli_stackmap_memory_usage *usage;

	time_t record_start_time;
	time_t day_start;

	struct stackmap_count_table *count_table;
	struct stackmap_timewheel *timewheel;
	struct id_count *id_count;

	pthread_mutex_t id_count_lock;
	pthread_mutex_t strmap_lock;
	pthread_mutex_t idsmap_lock;
};

/**
 * _stackmap_compare_count - compare two @id_count entries by descending count.
 * @a: first entry.
 * @b: second entry.
 *
 * Return: positive when @b has smaller count than @a.
 */
static inline int _stackmap_compare_count(struct id_count *a, struct id_count *b)
{
	return (b->count - a->count);
}

#endif
