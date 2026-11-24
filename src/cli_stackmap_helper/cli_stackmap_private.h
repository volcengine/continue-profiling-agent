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
#include "stackmap_arena.h"
#include "stackmap_count_table.h"
#include "stackmap_ids_codec.h"
#include "stackmap_intern_index.h"
#include "stackmap_timewheel.h"

/**
 * @file cli_stackmap_private.h
 * @brief Internal stackmap storage structures used by shared aggregator helpers.
 */

/**
 * struct stackmap_str_rec - a frame string of a live map, in its string arena.
 * @len: length of @str, without the terminating NUL.
 * @id: stable frame id.
 * @str: the string, NUL-terminated.
 */
struct stackmap_str_rec {
	uint32_t len;
	uint32_t id;
	char str[];
};

/*
 * str_hash and ids_hash are the entries of a store read back
 * (cli_stackmap_reload()); a live map keeps stackmap_str_rec and
 * stackmap_ids_codec.h records instead.
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
 * @str_index: string -> id index, over @str_rec_by_id.
 * @str_arena: storage of the string records.
 * @str_rec_by_id: id to string record.
 * @str_rec_maxlen: allocated size of @str_rec_by_id.
 * @dumped_str_id: last dumped string id.
 * @ids_id: next ids id to allocate.
 * @ids_index: encoded stack -> id index, over @ids_rec_by_id.
 * @ids_arena: storage of the stack records.
 * @ids_rec_by_id: id to stack record (stackmap_ids_codec.h): read through
 *                 FOR_EACH_STACKMAP_STR or cli_stackmap_ids_copy().
 * @ids_rec_maxlen: allocated size of @ids_rec_by_id.
 * @ids_key: the current entry encoded, the key @ids_index looks up.
 * @ids_key_cap: allocated size of @ids_key.
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
	struct stackmap_intern_index *str_index;
	struct stackmap_arena *str_arena;
	struct stackmap_str_rec **str_rec_by_id;
	uint32_t str_rec_maxlen;
	uint32_t dumped_str_id;

	uint32_t ids_id;
	struct stackmap_intern_index *ids_index;
	struct stackmap_arena *ids_arena;
	const uint8_t **ids_rec_by_id;
	uint32_t ids_rec_maxlen;
	uint8_t *ids_key;
	size_t ids_key_cap;
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
