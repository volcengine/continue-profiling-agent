// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: ByteDance Inc

#include "stackmap_count_table.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define STACKMAP_COUNT_INITIAL_CAP 16U
#define STACKMAP_COUNT_LOAD_NUM 3U
#define STACKMAP_COUNT_LOAD_DEN 4U

struct stackmap_count_table {
	uint32_t *keys;
	uint64_t *counts;
	uint8_t *used;
	uint32_t *touched_slots;
	size_t cap;
	size_t len;
	size_t touched_len;
	size_t touched_cap;
};

static uint32_t hash_u32(uint32_t value)
{
	value ^= value >> 16;
	value *= 0x7feb352dU;
	value ^= value >> 15;
	value *= 0x846ca68bU;
	value ^= value >> 16;
	return value;
}

static bool is_power_of_two(size_t value)
{
	return value && !(value & (value - 1));
}

static int table_alloc_arrays(struct stackmap_count_table *table, size_t cap)
{
	if (!is_power_of_two(cap) || cap > UINT32_MAX)
		return -1;

	table->keys = calloc(cap, sizeof(*table->keys));
	table->counts = calloc(cap, sizeof(*table->counts));
	table->used = calloc(cap, sizeof(*table->used));
	table->touched_slots = calloc(cap, sizeof(*table->touched_slots));
	if (!table->keys || !table->counts || !table->used ||
	    !table->touched_slots)
		return -1;

	table->cap = cap;
	table->touched_cap = cap;
	return 0;
}

static void table_free_arrays(struct stackmap_count_table *table)
{
	free(table->keys);
	free(table->counts);
	free(table->used);
	free(table->touched_slots);
	table->keys = NULL;
	table->counts = NULL;
	table->used = NULL;
	table->touched_slots = NULL;
	table->cap = 0;
	table->len = 0;
	table->touched_len = 0;
	table->touched_cap = 0;
}

struct stackmap_count_table *stackmap_count_table_create(void)
{
	struct stackmap_count_table *table = calloc(1, sizeof(*table));

	if (!table)
		return NULL;

	if (table_alloc_arrays(table, STACKMAP_COUNT_INITIAL_CAP) != 0) {
		table_free_arrays(table);
		free(table);
		return NULL;
	}

	return table;
}

void stackmap_count_table_destroy(struct stackmap_count_table *table)
{
	if (!table)
		return;

	table_free_arrays(table);
	free(table);
}

static size_t find_slot(const struct stackmap_count_table *table,
			uint32_t ids_id, bool *found)
{
	size_t mask = table->cap - 1;
	size_t slot = hash_u32(ids_id) & mask;

	while (table->used[slot]) {
		if (table->keys[slot] == ids_id) {
			*found = true;
			return slot;
		}
		slot = (slot + 1) & mask;
	}

	*found = false;
	return slot;
}

static int insert_known_new_at_slot(struct stackmap_count_table *table,
				    size_t slot, uint32_t ids_id,
				    uint64_t count)
{
	if (slot >= table->cap || table->used[slot])
		return -1;
	if (table->touched_len >= table->touched_cap)
		return -1;

	table->used[slot] = 1;
	table->keys[slot] = ids_id;
	table->counts[slot] = count;
	table->touched_slots[table->touched_len++] = (uint32_t)slot;
	table->len++;
	return 0;
}

static int insert_known_new(struct stackmap_count_table *table,
			    uint32_t ids_id, uint64_t count)
{
	bool found = false;
	size_t slot = find_slot(table, ids_id, &found);

	if (found)
		return -1;
	return insert_known_new_at_slot(table, slot, ids_id, count);
}

static int rehash_table(struct stackmap_count_table *table, size_t new_cap)
{
	struct stackmap_count_table next = { 0 };
	uint32_t *old_keys = table->keys;
	uint64_t *old_counts = table->counts;
	uint8_t *old_used = table->used;
	uint32_t *old_touched = table->touched_slots;
	size_t old_touched_len = table->touched_len;

	if (new_cap <= table->cap || new_cap > UINT32_MAX)
		return -1;

	if (table_alloc_arrays(&next, new_cap) != 0) {
		table_free_arrays(&next);
		return -1;
	}

	for (size_t i = 0; i < old_touched_len; i++) {
		uint32_t slot = old_touched[i];

		if (!old_used[slot])
			continue;
		if (insert_known_new(&next, old_keys[slot],
				     old_counts[slot]) != 0) {
			table_free_arrays(&next);
			return -1;
		}
	}

	table->keys = next.keys;
	table->counts = next.counts;
	table->used = next.used;
	table->touched_slots = next.touched_slots;
	table->cap = next.cap;
	table->len = next.len;
	table->touched_len = next.touched_len;
	table->touched_cap = next.touched_cap;

	free(old_keys);
	free(old_counts);
	free(old_used);
	free(old_touched);
	return 0;
}

static int ensure_insert_capacity(struct stackmap_count_table *table)
{
	size_t next_len = table->len + 1;

	if (next_len * STACKMAP_COUNT_LOAD_DEN <
	    table->cap * STACKMAP_COUNT_LOAD_NUM)
		return 0;
	if (table->cap > UINT32_MAX / 2)
		return -1;
	return rehash_table(table, table->cap * 2);
}

int stackmap_count_table_add(struct stackmap_count_table *table,
			     uint32_t ids_id, uint64_t count)
{
	bool found = false;
	size_t slot;
	size_t old_cap;

	if (!table)
		return -1;

	slot = find_slot(table, ids_id, &found);
	if (found) {
		table->counts[slot] += count;
		return 0;
	}

	old_cap = table->cap;
	if (ensure_insert_capacity(table) != 0)
		return -1;
	if (table->cap != old_cap) {
		slot = find_slot(table, ids_id, &found);
		if (found) {
			table->counts[slot] += count;
			return 0;
		}
	}

	return insert_known_new_at_slot(table, slot, ids_id, count);
}

bool stackmap_count_table_get(const struct stackmap_count_table *table,
			      uint32_t ids_id, uint64_t *count)
{
	bool found = false;
	size_t slot;

	if (!table)
		return false;

	slot = find_slot(table, ids_id, &found);
	if (!found)
		return false;
	if (count)
		*count = table->counts[slot];
	return true;
}

size_t stackmap_count_table_len(const struct stackmap_count_table *table)
{
	return table ? table->len : 0;
}

size_t stackmap_count_table_memory_usage(
	const struct stackmap_count_table *table)
{
	if (!table)
		return 0;

	return sizeof(*table) +
	       table->cap * (sizeof(*table->keys) +
			     sizeof(*table->counts) +
			     sizeof(*table->used)) +
	       table->touched_cap * sizeof(*table->touched_slots);
}

int stackmap_count_table_for_each(const struct stackmap_count_table *table,
				  stackmap_count_iter_fn fn, void *ctx)
{
	if (!table || !fn)
		return -1;

	for (size_t i = 0; i < table->touched_len; i++) {
		uint32_t slot = table->touched_slots[i];

		if (!table->used[slot])
			continue;
		if (fn(table->keys[slot], table->counts[slot], ctx) != 0)
			return -1;
	}

	return 0;
}

void stackmap_count_table_reset(struct stackmap_count_table *table)
{
	if (!table)
		return;

	for (size_t i = 0; i < table->touched_len; i++) {
		uint32_t slot = table->touched_slots[i];

		table->used[slot] = 0;
		table->keys[slot] = 0;
		table->counts[slot] = 0;
	}

	table->len = 0;
	table->touched_len = 0;
}

int stackmap_count_table_take_items(struct stackmap_count_table *table,
				    bool nonzero_only,
				    struct stackmap_count_item **items,
				    size_t *len)
{
	struct stackmap_count_item *out = NULL;
	size_t out_len = 0;

	if (!table || !items || !len)
		return -1;

	for (size_t i = 0; i < table->touched_len; i++) {
		uint32_t slot = table->touched_slots[i];

		if (!table->used[slot])
			continue;
		if (nonzero_only && table->counts[slot] == 0)
			continue;
		out_len++;
	}

	if (out_len) {
		out = malloc(out_len * sizeof(*out));
		if (!out)
			return -1;
	}

	size_t index = 0;
	for (size_t i = 0; i < table->touched_len; i++) {
		uint32_t slot = table->touched_slots[i];

		if (!table->used[slot])
			continue;
		if (nonzero_only && table->counts[slot] == 0)
			continue;
		out[index].ids_id = table->keys[slot];
		out[index].count = table->counts[slot];
		index++;
	}

	stackmap_count_table_reset(table);
	*items = out;
	*len = out_len;
	return 0;
}
