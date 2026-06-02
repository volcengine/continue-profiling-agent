// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include <cli_stackmap.h>
#include <uthash.h>
#include <cli_output.h>
#include <time.h>
#include <cli_common.h>
#include "cli_config.h"

#define DEFAULT_IDS_LEN 16

struct cli_stackmap_entry *cli_stackmap_entry_init(void)
{
	struct cli_stackmap_entry *entry = calloc(1, sizeof(struct cli_stackmap_entry));
	if (!entry) {
		CLI_ERROR("cli_stackmap_entry_init: malloc failed\n");
		return NULL;
	}

	entry->ids = calloc(DEFAULT_IDS_LEN, sizeof(uint32_t));
	if (!entry->ids) {
		CLI_ERROR("cli_stackmap_entry_init: malloc ids failed\n");
		free(entry);
		return NULL;
	}

	entry->ids_maxlen = DEFAULT_IDS_LEN;
	entry->ids_len = 0;

	return entry;
}

void cli_stackmap_entry_destroy(struct cli_stackmap_entry *entry)
{
	if (!entry)
		return;

	if (entry->ids)
		free(entry->ids);

	free(entry);
}

int cli_stackmap_current_length(struct cli_stackmap *map)
{
	struct cli_stackmap_entry *entry = map->current;
	if (!entry)
		return 0;

	return entry->ids_len;
}

void cli_stackmap_current_reset(struct cli_stackmap *map, int index)
{
	struct cli_stackmap_entry *entry = map->current;
	if (!entry)
		return;

	entry->last_reverse = index;
	entry->ids_len = index;
	memset(entry->ids + index, 0, (entry->ids_maxlen - index) * sizeof(uint32_t));
}

void cli_stackmap_print(struct cli_stackmap *map)
{
	struct cli_stackmap_entry *entry = map->current;
	if (!entry || !entry->ids_len) {
		CLI_OUTPUT("(empty stack)");
		return;
	}

	for (int i = 0; i < entry->ids_len; i++) {
		uint32_t id = entry->ids[i];
		struct str_hash *str = map->str_hash_by_id[id];
		if (str) {
			CLI_OUTPUT(" - %s", str->str);
		}
	}
}

struct cli_stackmap *cli_stackmap_init(void)
{
	struct cli_stackmap *map = calloc(1, sizeof(struct cli_stackmap));
	bool id_count_lock_inited = false;
	bool strmap_lock_inited = false;
	bool idsmap_lock_inited = false;

	if (!map) {
		CLI_ERROR("cli_stackmap_init: malloc map failed\n");
		return NULL;
	}

	map->current = cli_stackmap_entry_init();
	if (!map->current) {
		CLI_ERROR("cli_stackmap_entry_init: malloc failed\n");
		goto clear;
	}

	map->str_id = 1;
	map->str_hash_maxlen = DEFAULT_IDS_LEN;
	map->str_hash_by_id = calloc(DEFAULT_IDS_LEN, sizeof(struct str_hash *));
	if (!map->str_hash_by_id) {
		CLI_ERROR("cli_stackmap_entry_init: malloc str_hash failed\n");
		goto clear;
	}

	map->ids_id = 1;
	map->ids_hash_maxlen = DEFAULT_IDS_LEN;
	map->ids_hash_by_id = calloc(DEFAULT_IDS_LEN, sizeof(struct ids_hash *));
	if (!map->ids_hash_by_id) {
		CLI_ERROR("cli_stackmap_entry_init: malloc ids_hash failed\n");
		goto clear;
	}

	map->usage = calloc(1, sizeof(struct cli_stackmap_memory_usage));
	if (!map->usage) {
		CLI_ERROR("cli_stackmap_entry_init: malloc usage failed\n");
		goto clear;
	}

	map->count_table = stackmap_count_table_create();
	if (!map->count_table) {
		CLI_ERROR("cli_stackmap_entry_init: malloc count_table failed\n");
		goto clear;
	}

	if (pthread_mutex_init(&map->id_count_lock, NULL) != 0)
		goto clear;
	id_count_lock_inited = true;

	if (pthread_mutex_init(&map->strmap_lock, NULL) != 0)
		goto clear;
	strmap_lock_inited = true;

	if (pthread_mutex_init(&map->idsmap_lock, NULL) != 0)
		goto clear;
	idsmap_lock_inited = true;

	map->day_start = get_start_of_today() * 1000;

	return map;

clear:
	if (idsmap_lock_inited)
		pthread_mutex_destroy(&map->idsmap_lock);
	if (strmap_lock_inited)
		pthread_mutex_destroy(&map->strmap_lock);
	if (id_count_lock_inited)
		pthread_mutex_destroy(&map->id_count_lock);
	if (map && map->current)
		cli_stackmap_entry_destroy(map->current);
	if (map && map->str_hash_by_id)
		free(map->str_hash_by_id);
	if (map && map->ids_hash_by_id)
		free(map->ids_hash_by_id);
	if (map && map->count_table)
		stackmap_count_table_destroy(map->count_table);
	if (map && map->usage)
		free(map->usage);

	free(map);
	return NULL;
}

void cli_stackmap_destroy(struct cli_stackmap *map)
{
	struct str_hash *p, *tmp;
	struct ids_hash *p_id, *tmp_id;
	struct id_count *p_count, *tmp_count;

	if (!map)
		return;

	pthread_mutex_destroy(&map->id_count_lock);
	pthread_mutex_destroy(&map->strmap_lock);
	pthread_mutex_destroy(&map->idsmap_lock);

	if (map->idsmap)
		cli_zstd_destroy(map->idsmap);
	if (map->strmap)
		cli_zstd_destroy(map->strmap);
	if (map->stackmap)
		cli_zstd_destroy(map->stackmap);
	stackmap_timewheel_destroy(map->timewheel);
	stackmap_count_table_destroy(map->count_table);

	HASH_ITER (hh, map->str_hash, p, tmp) {
		HASH_DEL(map->str_hash, p);
		free(p->str);
		free(p);
	}

	HASH_ITER (hh, map->id_count, p_count, tmp_count) {
		HASH_DEL(map->id_count, p_count);
		free(p_count);
	}

	HASH_ITER (hh, map->ids_hash, p_id, tmp_id) {
		HASH_DEL(map->ids_hash, p_id);
		free(p_id);
	}

	if (map->current)
		cli_stackmap_entry_destroy(map->current);

	if (map->str_hash_by_id)
		free(map->str_hash_by_id);
	if (map->ids_hash_by_id)
		free(map->ids_hash_by_id);
	if (map->usage)
		free(map->usage);

	free(map);

	return;
}

int cli_stackmap_entry_append_id(struct cli_stackmap *map, struct cli_stackmap_entry *entry, uint32_t id)
{
	if (!map || !entry) {
		CLI_ERROR("input entry is NULL\n");
		return -1;
	}

	if (entry->ids_len >= entry->ids_maxlen) {
		pthread_mutex_lock(&map->idsmap_lock);
		entry->ids_maxlen *= 2;
		entry->ids = realloc(entry->ids, entry->ids_maxlen * sizeof(uint32_t));
		pthread_mutex_unlock(&map->idsmap_lock);
		if (!entry->ids) {
			CLI_ERROR("fatal: realloc ids failed\n");
			return -1;
		}
	}

	entry->ids[entry->ids_len] = id;
	entry->ids_len++;

	return 0;
}

uint64_t cli_stackmap_now_record_ms(struct cli_stackmap *map)
{
	if (!map)
		return 0;
	return get_current_ms() - map->day_start;
}

int cli_stackmap_append(struct cli_stackmap *map, const char *stack)
{
	struct str_hash *s;
	int ret = 0;

	if (!map) {
		CLI_ERROR("input map is NULL\n");
		return -1;
	}

	if (!map->record_start_time)
		map->record_start_time = get_current_ms() - map->day_start;

	HASH_FIND_STR(map->str_hash, stack, s);
	if (!s) {
		s = calloc(1, sizeof(struct str_hash));
		if (!s) {
			CLI_ERROR("malloc str_hash failed\n");
			return -1;
		}

		s->str = strdup(stack);
		map->usage->memory_usage_strmap += strlen(stack) + sizeof(struct str_hash);
		s->id = map->str_id++;

		HASH_ADD_KEYPTR(hh, map->str_hash, s->str, strlen(s->str), s);

		if (s->id >= map->str_hash_maxlen) {
			pthread_mutex_lock(&map->strmap_lock);
			int old_maxlen = map->str_hash_maxlen;
			while (s->id >= map->str_hash_maxlen)
				map->str_hash_maxlen *= 2;
			struct str_hash **new_arr = realloc(map->str_hash_by_id, map->str_hash_maxlen * sizeof(struct str_hash *));
			if (!new_arr) {
				pthread_mutex_unlock(&map->strmap_lock);
				CLI_ERROR("fatal: realloc str_hash_by_id failed\n");
				return -1;
			}
			map->str_hash_by_id = new_arr;
			memset(map->str_hash_by_id + old_maxlen, 0, (map->str_hash_maxlen - old_maxlen) * sizeof(struct str_hash *));
			pthread_mutex_unlock(&map->strmap_lock);
		}

		map->str_hash_by_id[s->id] = s;
	}

	ret = cli_stackmap_entry_append_id(map, map->current, s->id);
	if (ret) {
		CLI_ERROR("append id to current stackmap_entry failed\n");
		return -1;
	}

	return 0;
}

void cli_stackmap_entry_reverse_ids(struct cli_stackmap *map)
{
	struct cli_stackmap_entry *entry = map->current;
	if (!entry || !entry->ids_len || entry->last_reverse >= entry->ids_len)
		return;

	uint32_t start = entry->last_reverse;
	uint32_t end = entry->ids_len - 1;

	while (start < end) {
		uint32_t temp = entry->ids[start];
		entry->ids[start] = entry->ids[end];
		entry->ids[end] = temp;

		start++;
		end--;
	}

	entry->last_reverse = entry->ids_len;
}

void new_id_count(struct cli_stackmap *map, uint32_t id, uint64_t count)
{
	struct id_count *id_count;

	id_count = calloc(1, sizeof(struct id_count));
	if (!id_count)
		return;

	id_count->count = count;
	id_count->ids_id = id;

	pthread_mutex_lock(&map->id_count_lock);
	HASH_ADD_INT(map->id_count, ids_id, id_count);
	pthread_mutex_unlock(&map->id_count_lock);
}

static struct ids_hash *new_ids_hash(struct cli_stackmap *map, uint32_t *ids, int len)
{
	size_t ids_alloc_size = sizeof(struct ids_hash) + len * sizeof(uint32_t);
	struct ids_hash *ids_hash = calloc(1, ids_alloc_size);
	uint32_t id = map->ids_id;

	if (!ids_hash)
		return NULL;

	/* ensure capacity BEFORE writing by index */
	if (id >= map->ids_hash_maxlen) {
		pthread_mutex_lock(&map->idsmap_lock);
		int old_maxlen = map->ids_hash_maxlen;
		while (id >= map->ids_hash_maxlen)
			map->ids_hash_maxlen *= 2;
		struct ids_hash **new_arr = realloc(map->ids_hash_by_id, map->ids_hash_maxlen * sizeof(struct ids_hash *));
		if (!new_arr) {
			pthread_mutex_unlock(&map->idsmap_lock);
			CLI_ERROR("fatal: realloc ids_hash_by_id failed\n");
			free(ids_hash);
			return NULL;
		}
		map->ids_hash_by_id = new_arr;
		memset(map->ids_hash_by_id + old_maxlen, 0, (map->ids_hash_maxlen - old_maxlen) * sizeof(struct ids_hash *));
		pthread_mutex_unlock(&map->idsmap_lock);
	}

	map->usage->memory_usage_idsmap += ids_alloc_size;
	ids_hash->ids = (uint32_t *)(ids_hash + 1);
	ids_hash->id = id;
	ids_hash->ids_len = len;
	memcpy(ids_hash->ids, ids, len * sizeof(uint32_t));
	HASH_ADD_KEYPTR(hh, map->ids_hash, ids_hash->ids, ids_hash->ids_len * sizeof(uint32_t), ids_hash);
	map->ids_hash_by_id[ids_hash->id] = ids_hash;
	map->ids_id++;

	return ids_hash;
}

static int cli_stackmap_intern_current_ids(struct cli_stackmap *map, uint32_t *ids_id)
{
	struct ids_hash *ids_hash;

	if (!map) {
		CLI_ERROR("input map is NULL\n");
		return -1;
	}

	if (!map->current) {
		cli_stackmap_append(map, "<unknown>");
		if (!map->current) {
			CLI_ERROR("malloc current stackmap_entry failed\n");
			return -1;
		}
	}

	HASH_FIND(hh, map->ids_hash, map->current->ids, map->current->ids_len * sizeof(uint32_t), ids_hash);

	if (!ids_hash)
		ids_hash = new_ids_hash(map, map->current->ids, map->current->ids_len);
	if (!ids_hash)
		return -1;

	*ids_id = ids_hash->id;
	return 0;
}

int cli_stackmap_enable_timewheel(struct cli_stackmap *map, uint64_t hold_ms)
{
	struct stackmap_timewheel *timewheel;

	if (!map)
		return -1;
	if (map->timewheel)
		return 0;

	timewheel = stackmap_timewheel_create(hold_ms);
	if (!timewheel)
		return -1;

	map->timewheel = timewheel;
	return 0;
}

int cli_stackmap_done_at(struct cli_stackmap *map, uint64_t count, uint64_t record_ms)
{
	uint32_t ids_id = 0;
	int ret;

	if (!map || !map->timewheel)
		return cli_stackmap_done(map, count);
	if (cli_stackmap_intern_current_ids(map, &ids_id) != 0)
		return -1;

	pthread_mutex_lock(&map->id_count_lock);
	ret = stackmap_timewheel_add(map->timewheel, record_ms, ids_id, count);
	pthread_mutex_unlock(&map->id_count_lock);
	if (ret != 0) {
		CLI_ERROR("add stackmap timewheel count failed\n");
		return -1;
	}

	cli_stackmap_current_reset(map, 0);

	return 0;
}

int cli_stackmap_done(struct cli_stackmap *map, uint64_t count)
{
	struct id_count *id_count = NULL;
	uint32_t ids_id = 0;

	if (cli_stackmap_intern_current_ids(map, &ids_id) != 0)
		return -1;

	pthread_mutex_lock(&map->id_count_lock);
	HASH_FIND_INT(map->id_count, &ids_id, id_count);
	if (!id_count) {
		pthread_mutex_unlock(&map->id_count_lock);
		new_id_count(map, ids_id, count);
	} else {
		id_count->count += count;
		pthread_mutex_unlock(&map->id_count_lock);
	}

	cli_stackmap_current_reset(map, 0);

	return 0;
}

void cli_stackmap_append_procstack(struct cli_stackmap *map, const char *proc_stack)
{
	char *stack = strdup(proc_stack);
	char *line = strtok(stack, "\n");

	while (line != NULL) {
		char *start = strchr(line, ' ');
		if (start != NULL) {
			line = start + 1;
		}

		cli_stackmap_append(map, line);
		line = strtok(NULL, "\n");
	}

	cli_stackmap_entry_reverse_ids(map);

	free(stack);
}

void cli_stackmap_to_framegraph(struct cli_stackmap *map, FILE *fp)
{
	struct id_count *id_count;
	const char *s;

	if (!fp)
		printf("\n");

	FOR_EACH_STACKMAP_SORT_BY_COUNT(map, id_count)
	{
		FOR_EACH_STACKMAP_STR(map, id_count->ids_id, s)
		{
			if (fp)
				fprintf(fp, "%s;", s);
			else
				printf("%s;", s);
		}
		if (fp)
			fprintf(fp, " %ld\n", id_count->count);
		else
			printf(" %ld\n", id_count->count);
	}
}

#define DUMP_STR_BUF_SIZE 10 * 1024
char dump_buf[DUMP_STR_BUF_SIZE] = { 0 };

void cli_stackmap_dump_strmap(struct cli_stackmap *map, const char *file_name)
{
	if (!map->strmap) {
		map->strmap = cli_zstd_init(file_name);
		if (!map->strmap) {
			CLI_ERROR("cli_stackmap_zstd_init failed\n");
			return;
		}
	}

	int id = map->dumped_str_id;
	for (id = map->dumped_str_id; id <= map->str_id - 1; id++) {
		pthread_mutex_lock(&map->strmap_lock);
		struct str_hash *s = map->str_hash_by_id[id];
		pthread_mutex_unlock(&map->strmap_lock);
		if (!s)
			continue;

		cli_zstd_write(map->strmap, "%s %d\n", s->str, s->id);
		map->dumped_str_id = id + 1;
	}

	cli_zstd_write_done(map->strmap);
	cli_zstd_flush(map->strmap);
}

void cli_stackmap_dump_idsmap(struct cli_stackmap *map, const char *file_name)
{
	if (!map->idsmap) {
		map->idsmap = cli_zstd_init(file_name);
		if (!map->idsmap) {
			CLI_ERROR("cli_stackmap_zstd_init failed\n");
			return;
		}
	}

	int i = 0;

	int id = map->dumped_ids_id;
	for (id = map->dumped_ids_id; id <= map->ids_id - 1; id++) {
		pthread_mutex_lock(&map->idsmap_lock);
		struct ids_hash *s = map->ids_hash_by_id[id];
		pthread_mutex_unlock(&map->idsmap_lock);
		if (!s)
			continue;
		for (i = 0; i < s->ids_len; i++)
			cli_zstd_write(map->idsmap, "%d;", s->ids[i]);

		cli_zstd_write(map->idsmap, " %d\n", s->id);
		map->dumped_ids_id = id + 1;
		cli_zstd_write_done(map->idsmap);
	}

	cli_zstd_flush(map->idsmap);
}

static void _cli_stackmap_dump_stackmap_table(struct cli_stackmap *map, const char *file_name, uint64_t start, uint64_t end, struct stackmap_count_table *count_table)
{
	struct stackmap_count_item *id_counts = NULL;
	size_t id_count_len = 0;

	if (!count_table)
		return;

	if (!map->stackmap) {
		map->stackmap = cli_zstd_init(file_name);
		if (!map->stackmap) {
			CLI_ERROR("cli_stackmap_zstd_init failed\n");
			return;
		}
	}

	uint8_t header[] = { 0xFA, 0xFB };
	cli_zstd_write_bytes(map->stackmap, header, 2 * sizeof(uint8_t));

	uint64_t start_time = start;
	uint64_t end_time = end;

	/*
	 * stack.bin record layout:
	 * header, start_ms, end_ms, entry_count, repeated id/count pairs, footer.
	 */
	map->record_start_time = end_time;

	cli_zstd_write_bytes(map->stackmap, &start_time, sizeof(uint64_t));
	cli_zstd_write_bytes(map->stackmap, &end_time, sizeof(uint64_t));

	pthread_mutex_lock(&map->id_count_lock);
	if (stackmap_count_table_take_items(count_table, true, &id_counts, &id_count_len) != 0) {
		pthread_mutex_unlock(&map->id_count_lock);
		CLI_ERROR("Failed to drain stackmap count table");
		return;
	}
	pthread_mutex_unlock(&map->id_count_lock);

	uint64_t id_count_len_u64 = id_count_len;
	cli_zstd_write_bytes(map->stackmap, &id_count_len_u64, sizeof(uint64_t));

	for (size_t index = 0; index < id_count_len; index++) {
		cli_zstd_write_bytes(map->stackmap, &id_counts[index].ids_id, sizeof(uint32_t));
		cli_zstd_write_bytes(map->stackmap, &id_counts[index].count, sizeof(uint64_t));
	}

	free(id_counts);

	uint8_t footer[] = { 0xFC, 0xFD };

	cli_zstd_write_bytes(map->stackmap, footer, 2 * sizeof(uint8_t));

	cli_zstd_write_done(map->stackmap);

	cli_zstd_flush(map->stackmap);
}

static void _cli_stackmap_dump_stackmap(struct cli_stackmap *map, const char *file_name, uint64_t start, uint64_t end)
{
	struct id_count *id_count, *id_counts_tmp = NULL, *dump_id_count = NULL;

	if (!map->stackmap) {
		map->stackmap = cli_zstd_init(file_name);
		if (!map->stackmap) {
			CLI_ERROR("cli_stackmap_zstd_init failed\n");
			return;
		}
	}

	uint8_t header[] = { 0xFA, 0xFB };
	cli_zstd_write_bytes(map->stackmap, header, 2 * sizeof(uint8_t));

	uint64_t start_time = start;
	uint64_t end_time = end;

	map->record_start_time = end_time;

	cli_zstd_write_bytes(map->stackmap, &start_time, sizeof(uint64_t));
	cli_zstd_write_bytes(map->stackmap, &end_time, sizeof(uint64_t));

	uint64_t id_count_len = 0;

	pthread_mutex_lock(&map->id_count_lock);
	dump_id_count = map->id_count;
	map->id_count = NULL;
	pthread_mutex_unlock(&map->id_count_lock);

	FOR_EACH_ID_COUNT(dump_id_count, id_count)
	{
		if (!id_count->count)
			continue;
		id_count_len += 1;
	}

	if (id_count_len) {
		id_counts_tmp = malloc(id_count_len * sizeof(struct id_count));
		if (!id_counts_tmp) {
			CLI_ERROR("Failed to alloc id_counts_tmp");
			if (dump_id_count)
				cli_stackmap_dump_free(dump_id_count);
			return;
		}
	}

	uint64_t index = 0;

	FOR_EACH_ID_COUNT(dump_id_count, id_count)
	{
		if (!id_count->count)
			continue;

		id_counts_tmp[index].ids_id = id_count->ids_id;
		id_counts_tmp[index].count = id_count->count;
		index++;
		id_count->count = 0;
	}

	cli_zstd_write_bytes(map->stackmap, &id_count_len, sizeof(uint64_t));

	for (index = 0; index < id_count_len; index++) {
		id_count = &id_counts_tmp[index];

		cli_zstd_write_bytes(map->stackmap, &id_count->ids_id, sizeof(uint32_t));
		cli_zstd_write_bytes(map->stackmap, &id_count->count, sizeof(uint64_t));
	}

	if (dump_id_count)
		cli_stackmap_dump_free(dump_id_count);

	free(id_counts_tmp);

	uint8_t footer[] = { 0xFC, 0xFD };

	cli_zstd_write_bytes(map->stackmap, footer, 2 * sizeof(uint8_t));

	cli_zstd_write_done(map->stackmap);

	cli_zstd_flush(map->stackmap);
}

void cli_stackmap_dump_stackmap(struct cli_stackmap *map, const char *file_name)
{
	uint64_t start_time = map->record_start_time;
	uint64_t end_time = get_current_ms() - map->day_start;

	if (end_time >= 86400 * 1000)
		return;

	if (!start_time)
		start_time = end_time;

	_cli_stackmap_dump_stackmap(map, file_name, start_time, end_time);
}

struct dump_timewheel_ctx {
	struct cli_stackmap *stackmap;
	const char *stackmap_file;
	uint64_t last_end_ms;
	bool flushed;
};

static int cli_stackmap_dump_timewheel_bucket(uint64_t start_ms, uint64_t end_ms, struct stackmap_count_table *counts, void *arg)
{
	struct dump_timewheel_ctx *ctx = arg;

	_cli_stackmap_dump_stackmap_table(ctx->stackmap, ctx->stackmap_file, start_ms, end_ms, counts);
	ctx->last_end_ms = end_ms;
	ctx->flushed = true;
	return 0;
}

static void cli_stackmap_dump_timewheel_sentinel(struct cli_stackmap *stackmap, const char *stackmap_file, uint64_t end_record_ms)
{
	if (end_record_ms >= 86400 * 1000)
		return;

	/* Zero-length guard record marks that the previous bucket is complete. */
	_cli_stackmap_dump_stackmap_table(stackmap, stackmap_file, end_record_ms, end_record_ms, stackmap->count_table);
}

static void cli_stackmap_dump_delta_stack_common(struct cli_stackmap *stackmap, const char *dir, uint64_t now_record_ms, bool flush_all)
{
	char *strmap_file = path_join(dir, "strmap");
	char *idsmap_file = path_join(dir, "idsmap");
	char *stackmap_file = path_join(dir, "stack.bin");
	struct dump_timewheel_ctx timewheel_ctx = {
		.stackmap = stackmap,
		.stackmap_file = stackmap_file,
	};

	cli_stackmap_dump_strmap(stackmap, strmap_file);
	cli_stackmap_dump_idsmap(stackmap, idsmap_file);
	if (stackmap->timewheel) {
		/*
		 * Timewheel mode emits complete second buckets plus a guard record.
		 * Legacy mode writes one raw interval record.
		 */
		if (flush_all) {
			stackmap_timewheel_flush_all(stackmap->timewheel, cli_stackmap_dump_timewheel_bucket, &timewheel_ctx);
		} else {
			stackmap_timewheel_flush_ready(stackmap->timewheel, now_record_ms, cli_stackmap_dump_timewheel_bucket, &timewheel_ctx);
		}
		if (timewheel_ctx.flushed) {
			cli_stackmap_dump_timewheel_sentinel(stackmap, stackmap_file, timewheel_ctx.last_end_ms);
		}
	} else {
		cli_stackmap_dump_stackmap(stackmap, stackmap_file);
	}

	free(strmap_file);
	free(idsmap_file);
	free(stackmap_file);

	return;
}

void cli_stackmap_dump_delta_stack_at(struct cli_stackmap *stackmap, const char *dir, uint64_t now_record_ms)
{
	cli_stackmap_dump_delta_stack_common(stackmap, dir, now_record_ms, false);
}

void cli_stackmap_dump_delta_stack_flush_all(struct cli_stackmap *stackmap, const char *dir, uint64_t now_record_ms)
{
	cli_stackmap_dump_delta_stack_common(stackmap, dir, now_record_ms, true);
}

void cli_stackmap_dump_delta_stack(struct cli_stackmap *stackmap, const char *dir)
{
	cli_stackmap_dump_delta_stack_at(stackmap, dir, cli_stackmap_now_record_ms(stackmap));
}

struct cli_stackmap_memory_usage *cli_stackmap_get_memory_usage(struct cli_stackmap *map)
{
	if (!map)
		return NULL;
	map->usage->memory_usage_strarray = map->str_hash_maxlen * sizeof(void *);
	map->usage->memory_usage_idsarray = map->ids_hash_maxlen * sizeof(void *);
	return map->usage;
}

int cli_stackmap_fetch_dump_info(const char *dir_name, struct stackmap_dump_info *dump_info, int use_cache)
{
	char *file_name = path_join(dir_name, "stack.bin");
	char *decompress_path = cli_zstd_decompress_file(file_name, use_cache);
	free(file_name);

	if (!decompress_path) {
		CLI_ERROR("Failed to decompress stack.bin");
		return -1;
	}

	FILE *file = fopen(decompress_path, "rb");
	if (!file) {
		CLI_ERROR("Failed to open file");
		free(decompress_path);
		return -1;
	}

	memset(dump_info, 0, sizeof(struct stackmap_dump_info));
	uint8_t header[2];
	uint8_t footer[2];
	uint64_t starttime;
	uint64_t endtime;
	uint64_t record_count;
	uint64_t file_offset = 0;
	size_t record_capacity = 16;

	/*
	 * Parsing is footer-driven: after each header section, seek to the
	 * expected footer and validate it to keep the stream scan synchronized.
	 */
	dump_info->records = malloc(record_capacity * sizeof(struct stackmap_record));
	if (!dump_info->records) {
		CLI_ERROR("Failed to allocate initial memory for records");
		fclose(file);
		free(decompress_path);
		return -1;
	}

	while (fread(header, sizeof(uint8_t), 2, file) == 2 && header[0] == 0xFA && header[1] == 0xFB) {
		file_offset += 2;

		if (fread(&starttime, sizeof(uint64_t), 1, file) != 1) {
			CLI_ERROR("Failed to read starttime");
			goto failed;
		}

		if (fread(&endtime, sizeof(uint64_t), 1, file) != 1) {
			CLI_ERROR("Failed to read endtime");
			goto failed;
		}

		if (fread(&record_count, sizeof(uint64_t), 1, file) != 1) {
			CLI_ERROR("Failed to read record count");
			goto failed;
		}

		if (dump_info->record_count == 0) {
			dump_info->start = starttime;
		}
		if (endtime < dump_info->start)
			endtime += 86400 * 1000;
		dump_info->end = endtime;

		if (dump_info->record_count >= record_capacity) {
			record_capacity *= 2;
			struct stackmap_record *new_records = realloc(dump_info->records, record_capacity * sizeof(struct stackmap_record));
			if (!new_records) {
				CLI_ERROR("Failed to reallocate memory for records");
				goto failed;
			}
			dump_info->records = new_records;
		}

		struct stackmap_record *record = &dump_info->records[dump_info->record_count];
		record->starttime = starttime;
		record->endtime = endtime;
		record->file_off = file_offset;
		record->count = record_count;

		dump_info->record_count++;

		file_offset += sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint64_t) + record_count * (sizeof(uint32_t) + sizeof(uint64_t)) + sizeof(uint8_t) * 2;
		/* file_offset is the next header; footer starts two bytes earlier. */
		fseek(file, file_offset - 2, SEEK_SET);

		if (fread(footer, sizeof(uint8_t), 2, file) != 2 || footer[0] != 0xFC || footer[1] != 0xFD) {
			CLI_ERROR("Failed to read file footer or invalid footer");
			goto failed;
		}
	}

	if (dump_info->record_count == 0) {
		CLI_ERROR("No valid records found in stack.bin");
		goto failed;
	}

	if (decompress_path)
		free(decompress_path);

	fclose(file);
	return 0;

failed:
	if (decompress_path)
		free(decompress_path);

	if (dump_info->records) {
		free(dump_info->records);
		dump_info->records = NULL;
	}
	memset(dump_info, 0, sizeof(struct stackmap_dump_info));
	fclose(file);
	return -1;
}

struct id_count *cli_stackmap_dump(const char *dir_name, struct stackmap_record *records, int num)
{
	int record_index = 0;

	struct id_count *id_count_all = NULL;

	char *file_name = path_join(dir_name, "decompressed/stack.bin");

	FILE *file = fopen(file_name, "rb");
	if (!file) {
		CLI_ERROR("Failed to open file");
		free(file_name);
		return NULL;
	}

	free(file_name);

	for (record_index = 0; record_index < num; record_index++) {
		if (fseek(file, records->file_off + sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint64_t), SEEK_SET) != 0) {
			CLI_ERROR("Failed to seek in file");
			fclose(file);
			return NULL;
		}

		for (uint64_t i = 0; i < records->count; ++i) {
			struct id_count *id_count = calloc(1, sizeof(struct id_count));
			if (!id_count)
				continue;

			if (fread(&id_count->ids_id, sizeof(uint32_t), 1, file) != 1 || fread(&id_count->count, sizeof(uint64_t), 1, file) != 1) {
				CLI_ERROR("Failed to read id_count");
				fclose(file);
				return NULL;
			}
			struct id_count *id_hash = NULL;

			HASH_FIND_INT(id_count_all, &id_count->ids_id, id_hash);
			if (id_hash) {
				id_hash->count += id_count->count;
				free(id_count);
				continue;
			}

			HASH_ADD_INT(id_count_all, ids_id, id_count);
		}

		records++;
	}

	fclose(file);
	return id_count_all;
}

void cli_stackmap_dump_free(struct id_count *id_count_all)
{
	struct id_count *id_count, *tmp;
	HASH_ITER (hh, id_count_all, id_count, tmp) {
		HASH_DEL(id_count_all, id_count);
		free(id_count);
	}
}

typedef void (*line_processor_func)(const char *text, int num, void *ctx);

void process_file_by_line(const char *file_name, line_processor_func func, void *ctx)
{
	if (!file_name) {
		CLI_ERROR("process_file_by_line: file_name is NULL");
		return;
	}
	FILE *file = fopen(file_name, "r");
	if (!file) {
		perror("Failed to open file");
		return;
	}

	char *line = NULL;
	size_t len = 0;

	while (getline(&line, &len, file) != -1) {
		char *last_space = strrchr(line, ' ');
		if (last_space) {
			*last_space = '\0';
			int num = atoi(last_space + 1);
			func(line, num, ctx);
		} else {
			perror("Invalid line format");
		}
	}

	free(line);
	fclose(file);
}

void strmap_handler(const char *text, int num, void *ctx)
{
	struct cli_stackmap_record_map *map = (struct cli_stackmap_record_map *)ctx;

	struct str_hash *str_hash = calloc(1, sizeof(struct str_hash));
	if (!str_hash)
		return;

	str_hash->str = strdup(text);
	str_hash->id = num;

	HASH_ADD_INT(map->str, id, str_hash);
}

void idsmap_handler(const char *text, int num, void *ctx)
{
	struct cli_stackmap_record_map *map = (struct cli_stackmap_record_map *)ctx;

	struct ids_hash *ids_hash = calloc(1, sizeof(struct ids_hash));
	if (!ids_hash)
		return;

	size_t capacity = 1;
	ids_hash->ids = calloc(capacity, sizeof(uint32_t));

	const char *start = text;
	char *end;
	while (*start) {
		uint32_t num = strtoul(start, &end, 10);
		if (start == end)
			break;

		if (*end != ';') {
			CLI_ERROR("Invalid format");
			goto clear;
		}

		ids_hash->ids[ids_hash->ids_len++] = num;

		if (ids_hash->ids_len == capacity) {
			capacity *= 2;
			uint32_t *new = realloc(ids_hash->ids, capacity * sizeof(uint32_t));
			if (!new) {
				CLI_ERROR("Failed to reallocate memory");
				goto clear;
			}
			ids_hash->ids = new;
		}

		start = end + 1;
	}

	ids_hash->id = num;

	HASH_ADD_INT(map->ids, id, ids_hash);

	return;
clear:
	free(ids_hash->ids);
	free(ids_hash);
}

struct cli_stackmap_record_map *cli_stackmap_reload(const char *dir_name, int use_cache)
{
	struct cli_stackmap_record_map *map = calloc(1, sizeof(struct cli_stackmap_record_map));
	if (!map) {
		CLI_ERROR("Failed to allocate memory for map");
		return NULL;
	}

	char *strmap = path_join(dir_name, "strmap");
	char *decompress_path = cli_zstd_decompress_file(strmap, use_cache);
	if (!decompress_path) {
		CLI_ERROR("Failed to decompress strmap: %s", strmap);
		free(strmap);
		cli_stackmap_record_map_free(map);
		return NULL;
	}
	process_file_by_line(decompress_path, strmap_handler, map);
	free(strmap);
	free(decompress_path);

	char *idsmap = path_join(dir_name, "idsmap");
	char *idsmap_decompress_path = cli_zstd_decompress_file(idsmap, use_cache);
	if (!idsmap_decompress_path) {
		CLI_ERROR("Failed to decompress idsmap: %s", idsmap);
		free(idsmap);
		cli_stackmap_record_map_free(map);
		return NULL;
	}
	process_file_by_line(idsmap_decompress_path, idsmap_handler, map);
	free(idsmap);
	free(idsmap_decompress_path);

	return map;
}

void cli_stackmap_record_map_free(struct cli_stackmap_record_map *map)
{
	if (!map)
		return;

	struct str_hash *str_hash, *tmp;
	HASH_ITER (hh, map->str, str_hash, tmp) {
		HASH_DEL(map->str, str_hash);
		free(str_hash->str);
		free(str_hash);
	}

	struct ids_hash *ids_hash, *tmp2;
	HASH_ITER (hh, map->ids, ids_hash, tmp2) {
		HASH_DEL(map->ids, ids_hash);
		free(ids_hash->ids);
		free(ids_hash);
	}

	free(map);
}

void cli_stackmap_split(struct stackmap_record *records, int num, const char *source_dir, const char *target_dir, int use_cache)
{
	struct cli_stackmap_record_map *map = cli_stackmap_reload(source_dir, use_cache);
	if (!map) {
		CLI_ERROR("Failed to reload metadata for split");
		return;
	}

	struct cli_stackmap *split_map = cli_stackmap_init();

	struct stackmap_record *record = NULL;
	struct id_count *id_count_all = NULL;
	struct id_count *id_count;

	char *strmap_file = path_join(target_dir, "strmap");
	char *idsmap_file = path_join(target_dir, "idsmap");
	char *stackmap_file = path_join(target_dir, "stack.bin");

	for (int record_index = 0; record_index < num; record_index++) {
		record = &records[record_index];
		id_count_all = cli_stackmap_dump(source_dir, record, 1);

		FOR_EACH_ID_COUNT_SORT_BY_COUNT(id_count_all, id_count)
		{
			struct ids_hash *ids = NULL;
			HASH_FIND_INT(map->ids, &id_count->ids_id, ids);

			if (!ids)
				continue;

			struct str_hash *str = NULL;

			for (int i = 0; i < ids->ids_len; i++) {
				const char *resolved_frame = "<# STRMAP LOST ID #>";
				HASH_FIND_INT(map->str, &ids->ids[i], str);
				if (str && str->str) {
					resolved_frame = str->str;
				}
				cli_stackmap_append(split_map, resolved_frame);
			}
			cli_stackmap_done(split_map, id_count->count);
		}

		cli_stackmap_dump_strmap(split_map, strmap_file);
		cli_stackmap_dump_idsmap(split_map, idsmap_file);
		_cli_stackmap_dump_stackmap(split_map, stackmap_file, record->starttime, record->endtime);

		cli_stackmap_dump_free(id_count_all);
	}

	free(strmap_file);
	free(idsmap_file);
	free(stackmap_file);

	cli_stackmap_destroy(split_map);
	cli_stackmap_record_map_free(map);
}
