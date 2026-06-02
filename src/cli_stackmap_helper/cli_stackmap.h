// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef __CLI_STACKMAP_H__
#define __CLI_STACKMAP_H__

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <cli_stackmap_private.h>

/**
 * @file cli_stackmap.h
 * @brief Public stack aggregation and dump/reload helpers for CPA profiles.
 */

/**
 * struct cli_stackmap_memory_usage - memory usage counters of stackmap internals.
 * @memory_usage_strmap: bytes allocated for string hash stream.
 * @memory_usage_idsmap: bytes allocated for ids hash stream.
 * @memory_usage_strarray: bytes allocated for string array table.
 * @memory_usage_idsarray: bytes allocated for ids array table.
 */
struct cli_stackmap_memory_usage {
	uint64_t memory_usage_strmap;
	uint64_t memory_usage_idsmap;
	uint64_t memory_usage_strarray;
	uint64_t memory_usage_idsarray;
};

/**
 * struct stackmap_record - one stack dump record summary.
 * @starttime: interval start time.
 * @endtime: interval end time.
 * @count: sample count for the interval.
 * @file_off: record file offset.
 * @id_count: aggregated counts for the recorded interval.
 */
struct stackmap_record {
	uint64_t starttime;
	uint64_t endtime;
	uint64_t count;
	uint64_t file_off;
	struct id_count *id_count;
};

/**
 * struct stackmap_dump_info - metadata for decoded stack.bin records.
 * @start: start timestamp of earliest record.
 * @end: end timestamp of latest record.
 * @record_count: number of records.
 * @records: record array.
 */
struct stackmap_dump_info {
	uint64_t start;
	uint64_t end;
	uint64_t record_count;
	struct stackmap_record *records;
};

/**
 * struct cli_stackmap_record_map - decoded map metadata for reload/split.
 * @str: decoded string map table.
 * @ids: decoded ids map table.
 */
struct cli_stackmap_record_map {
	struct str_hash *str;
	struct ids_hash *ids;
};

/**
 * cli_stackmap_init - allocate an empty stackmap instance.
 *
 * Return: new stackmap on success, %NULL on failure.
 */
struct cli_stackmap *cli_stackmap_init(void);

/**
 * cli_stackmap_destroy - release a stackmap and internal caches.
 * @map: stackmap instance.
 */
void cli_stackmap_destroy(struct cli_stackmap *map);

/**
 * cli_stackmap_append - append one frame string to current stack entry.
 * @map: target stackmap.
 * @stack_frame: frame string to append.
 *
 * Return: 0 on success, negative on failure.
 */
int cli_stackmap_append(struct cli_stackmap *map, const char *stack_frame);

/**
 * cli_stackmap_done - close current frame list and emit/aggregate count.
 * @map: target stackmap.
 * @count: sample count for the current stack.
 *
 * Return: 0 on success, negative on failure.
 */
int cli_stackmap_done(struct cli_stackmap *map, uint64_t count);

/**
 * cli_stackmap_enable_timewheel - enable delayed count buckets for a stackmap.
 * @map: target stackmap.
 * @hold_ms: delay window before a bucket can be flushed.
 *
 * Return: 0 on success, negative on failure.
 */
int cli_stackmap_enable_timewheel(struct cli_stackmap *map, uint64_t hold_ms);

/**
 * cli_stackmap_done_at - close current frame list with an explicit timestamp.
 * @map: target stackmap.
 * @count: sample count for the current stack.
 * @record_ms: sample timestamp in milliseconds from the map day start.
 *
 * Return: 0 on success, negative on failure.
 */
int cli_stackmap_done_at(struct cli_stackmap *map, uint64_t count,
			 uint64_t record_ms);

/**
 * cli_stackmap_now_record_ms - return current milliseconds from map day start.
 * @map: target stackmap.
 *
 * Return: current record timestamp, or 0 on invalid input.
 */
uint64_t cli_stackmap_now_record_ms(struct cli_stackmap *map);

/**
 * cli_stackmap_current_length - get current frame count in active entry.
 * @map: target stackmap.
 *
 * Return: number of frames in current entry.
 */
int cli_stackmap_current_length(struct cli_stackmap *map);

/**
 * cli_stackmap_current_reset - reset active entry from index.
 * @map: target stackmap.
 * @index: new current frame index.
 */
void cli_stackmap_current_reset(struct cli_stackmap *map, int index);

/**
 * cli_stackmap_print - print current stack entry to CLI output helper.
 * @map: target stackmap.
 */
void cli_stackmap_print(struct cli_stackmap *map);

/**
 * cli_stackmap_entry_reverse_ids - reverse ids in current entry for flamegraph.
 * @map: target stackmap.
 */
void cli_stackmap_entry_reverse_ids(struct cli_stackmap *map);

/**
 * cli_stackmap_append_procstack - append multi-line process stack in one call.
 * @map: target stackmap.
 * @proc_stack: process stack text.
 */
void cli_stackmap_append_procstack(struct cli_stackmap *map, const char *proc_stack);

/**
 * cli_stackmap_to_framegraph - emit folded stack lines for flamegraph tools.
 * @map: target stackmap.
 * @fp: output file pointer.
 */
void cli_stackmap_to_framegraph(struct cli_stackmap *map, FILE *fp);

/**
 * cli_stackmap_get_memory_usage - query stackmap memory usage counters.
 * @map: target stackmap.
 *
 * Return: memory usage snapshot, or %NULL on invalid input.
 */
struct cli_stackmap_memory_usage *cli_stackmap_get_memory_usage(struct cli_stackmap *map);

/**
 * cli_stackmap_dump_delta_stack - persist maps for one stackmap interval.
 * @stackmap: source stackmap.
 * @dir: output directory.
 */
void cli_stackmap_dump_delta_stack(struct cli_stackmap *stackmap, const char *dir);

/**
 * cli_stackmap_dump_delta_stack_at - persist ready stackmap intervals.
 * @stackmap: source stackmap.
 * @dir: output directory.
 * @now_record_ms: current time in milliseconds from the map day start.
 */
void cli_stackmap_dump_delta_stack_at(struct cli_stackmap *stackmap,
				      const char *dir,
				      uint64_t now_record_ms);

/**
 * cli_stackmap_dump_delta_stack_flush_all - persist all pending intervals.
 * @stackmap: source stackmap.
 * @dir: output directory.
 * @now_record_ms: current time in milliseconds from the map day start.
 */
void cli_stackmap_dump_delta_stack_flush_all(struct cli_stackmap *stackmap,
					     const char *dir,
					     uint64_t now_record_ms);

/**
 * cli_stackmap_fetch_dump_info - parse stack dump footer/indexes.
 * @dir_name: directory containing stack.bin.
 * @dump_info: destination metadata.
 * @use_cache: non-zero to reuse decompressed file cache.
 *
 * Return: 0 on success, negative on failure.
 */
int cli_stackmap_fetch_dump_info(const char *dir_name, struct stackmap_dump_info *dump_info, int use_cache);

/**
 * cli_stackmap_dump - read selected dump records and aggregate counters.
 * @dir_name: source stack directory.
 * @records: input records.
 * @num: number of records.
 *
 * Return: aggregated id_count list, or %NULL on failure.
 */
struct id_count *cli_stackmap_dump(const char *dir_name, struct stackmap_record *records, int num);

/**
 * cli_stackmap_dump_free - free list allocated by @cli_stackmap_dump.
 * @id_count_all: aggregated result list.
 */
void cli_stackmap_dump_free(struct id_count *id_count_all);

/**
 * cli_stackmap_reload - load string and stack-id metadata from directory.
 * @dir_name: source directory.
 * @use_cache: non-zero to reuse decompressed cache files.
 *
 * Return: newly loaded map metadata or %NULL on failure.
 */
struct cli_stackmap_record_map *cli_stackmap_reload(const char *dir_name, int use_cache);

/**
 * cli_stackmap_record_map_free - release resources returned by @cli_stackmap_reload.
 * @map: map returned by @cli_stackmap_reload.
 */
void cli_stackmap_record_map_free(struct cli_stackmap_record_map *map);

/**
 * cli_stackmap_split - split selected records into target directory.
 * @records: input records.
 * @num: record count.
 * @source_dir: source directory.
 * @target_dir: destination directory.
 * @use_cache: non-zero to reuse decompressed file cache.
 */
void cli_stackmap_split(struct stackmap_record *records, int num, const char *source_dir, const char *target_dir, int use_cache);

/**
 * FOR_EACH_STACKMAP_SORT_BY_COUNT - iterate stackmap buckets ordered by count.
 * @map: source stackmap.
 * @id_count: loop cursor.
 */
#define FOR_EACH_STACKMAP_SORT_BY_COUNT(_map, _id_count)                                                                                                                                                                                                       \
	HASH_SORT((_map->id_count), _stackmap_compare_count);                                                                                                                                                                                                  \
	for ((_id_count) = _map->id_count; (_id_count); (_id_count) = (_id_count)->hh.next)

/**
 * FOR_EACH_ID_COUNT_SORT_BY_COUNT - iterate a list ordered by count.
 * @id_count: source list.
 * @id_count_p: loop cursor.
 */
#define FOR_EACH_ID_COUNT_SORT_BY_COUNT(_id_count, _id_count_p)                                                                                                                                                                                                \
	HASH_SORT((_id_count), _stackmap_compare_count);                                                                                                                                                                                                       \
	for ((_id_count_p) = (_id_count); (_id_count_p); (_id_count_p) = (_id_count_p)->hh.next)

/**
 * FOR_EACH_ID_COUNT - iterate id_count list in natural order.
 * @id_count: source list.
 * @id_count_p: loop cursor.
 */
#define FOR_EACH_ID_COUNT(_id_count, _id_count_p) for ((_id_count_p) = _id_count; (_id_count_p); (_id_count_p) = (_id_count_p)->hh.next)

/**
 * FOR_EACH_STACKMAP - iterate stackmap aggregation entries.
 * @map: source stackmap.
 * @id_count: loop cursor.
 */
#define FOR_EACH_STACKMAP(_map, _id_count) for ((_id_count) = (_map)->id_count; (_id_count); (_id_count) = (_id_count)->hh.next)

/**
 * FOR_EACH_STACKMAP_STR - iterate resolved frame strings for one stack id.
 * @map: stackmap context.
 * @_id: ids identifier.
 * @_str: resolved frame string for current iteration.
 */
#define FOR_EACH_STACKMAP_STR(_map, _id, _str)                                                                                                                                                                                                                 \
	struct ids_hash *_ids = (_map)->ids_hash_by_id[_id];                                                                                                                                                                                                   \
	int _sm_i;                                                                                                                                                                                                                                             \
	for (_sm_i = 0; _sm_i < (_ids)->ids_len && ((_str) = (_map)->str_hash_by_id[(_ids)->ids[_sm_i]]->str); _sm_i++)

#endif
