// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "stackmap_intern_index.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define STACKMAP_INTERN_INITIAL_CAP 16U
#define STACKMAP_INTERN_LOAD_NUM 7U
#define STACKMAP_INTERN_LOAD_DEN 8U

struct stackmap_intern_index {
	uint32_t *ids;
	uint32_t *hashes;
	uint8_t *used;
	size_t cap;
	size_t len;
	size_t max_probe_len;
	uint64_t total_probe_len;
};

static uint32_t hash_bytes(const void *key, size_t key_len)
{
	const uint8_t *bytes = key;
	uint32_t hash = 2166136261U;

	for (size_t i = 0; i < key_len; i++) {
		hash ^= bytes[i];
		hash *= 16777619U;
	}

	hash ^= hash >> 16;
	hash *= 0x7feb352dU;
	hash ^= hash >> 15;
	hash *= 0x846ca68bU;
	hash ^= hash >> 16;
	return hash;
}

static bool is_power_of_two(size_t value)
{
	return value && !(value & (value - 1));
}

static int index_alloc_arrays(struct stackmap_intern_index *index, size_t cap)
{
	if (!is_power_of_two(cap) || cap > UINT32_MAX)
		return -1;

	index->ids = calloc(cap, sizeof(*index->ids));
	index->hashes = calloc(cap, sizeof(*index->hashes));
	index->used = calloc(cap, sizeof(*index->used));
	if (!index->ids || !index->hashes || !index->used)
		return -1;

	index->cap = cap;
	return 0;
}

static void index_free_arrays(struct stackmap_intern_index *index)
{
	free(index->ids);
	free(index->hashes);
	free(index->used);
	index->ids = NULL;
	index->hashes = NULL;
	index->used = NULL;
	index->cap = 0;
	index->len = 0;
	index->max_probe_len = 0;
	index->total_probe_len = 0;
}

struct stackmap_intern_index *stackmap_intern_index_create(void)
{
	struct stackmap_intern_index *index = calloc(1, sizeof(*index));

	if (!index)
		return NULL;

	if (index_alloc_arrays(index, STACKMAP_INTERN_INITIAL_CAP) != 0) {
		index_free_arrays(index);
		free(index);
		return NULL;
	}

	return index;
}

void stackmap_intern_index_destroy(struct stackmap_intern_index *index)
{
	if (!index)
		return;

	index_free_arrays(index);
	free(index);
}

static size_t find_slot_by_hash(const struct stackmap_intern_index *index,
				uint32_t hash, const void *key, size_t key_len,
				stackmap_intern_index_eq_fn eq, void *ctx,
				bool *found)
{
	size_t mask = index->cap - 1;
	size_t slot = hash & mask;

	while (index->used[slot]) {
		if (index->hashes[slot] == hash &&
		    eq(index->ids[slot], key, key_len, ctx)) {
			*found = true;
			return slot;
		}
		slot = (slot + 1) & mask;
	}

	*found = false;
	return slot;
}

bool stackmap_intern_index_find(const struct stackmap_intern_index *index,
				const void *key, size_t key_len,
				stackmap_intern_index_eq_fn eq, void *ctx,
				uint32_t *id)
{
	bool found = false;
	size_t slot;

	if (!index || !eq || (!key && key_len > 0))
		return false;

	slot = find_slot_by_hash(index, hash_bytes(key, key_len), key, key_len,
				 eq, ctx, &found);
	if (!found)
		return false;
	if (id)
		*id = index->ids[slot];
	return true;
}

static size_t find_empty_slot_by_hash(const struct stackmap_intern_index *index,
				      uint32_t hash)
{
	size_t mask = index->cap - 1;
	size_t slot = hash & mask;

	while (index->used[slot])
		slot = (slot + 1) & mask;
	return slot;
}

static size_t probe_len_for_hash_slot(const struct stackmap_intern_index *index,
				      uint32_t hash, size_t slot)
{
	size_t mask = index->cap - 1;
	size_t ideal = hash & mask;

	return ((slot + index->cap - ideal) & mask) + 1;
}

static void record_probe_len(struct stackmap_intern_index *index,
			     uint32_t hash, size_t slot)
{
	size_t probe_len = probe_len_for_hash_slot(index, hash, slot);

	index->total_probe_len += probe_len;
	if (probe_len > index->max_probe_len)
		index->max_probe_len = probe_len;
}

static void insert_known_new(struct stackmap_intern_index *index,
			     uint32_t hash, uint32_t id)
{
	size_t slot = find_empty_slot_by_hash(index, hash);

	index->used[slot] = 1;
	index->hashes[slot] = hash;
	index->ids[slot] = id;
	index->len++;
	record_probe_len(index, hash, slot);
}

static int insert_known_new_at_slot(struct stackmap_intern_index *index,
				    size_t slot, uint32_t hash, uint32_t id)
{
	if (slot >= index->cap || index->used[slot])
		return -1;

	index->used[slot] = 1;
	index->hashes[slot] = hash;
	index->ids[slot] = id;
	index->len++;
	record_probe_len(index, hash, slot);
	return 0;
}

static int rehash_index(struct stackmap_intern_index *index, size_t new_cap)
{
	struct stackmap_intern_index next = { 0 };
	uint32_t *old_ids = index->ids;
	uint32_t *old_hashes = index->hashes;
	uint8_t *old_used = index->used;
	size_t old_cap = index->cap;

	if (new_cap <= old_cap || new_cap > UINT32_MAX)
		return -1;

	if (index_alloc_arrays(&next, new_cap) != 0) {
		index_free_arrays(&next);
		return -1;
	}

	for (size_t i = 0; i < old_cap; i++) {
		if (old_used[i])
			insert_known_new(&next, old_hashes[i], old_ids[i]);
	}

	index->ids = next.ids;
	index->hashes = next.hashes;
	index->used = next.used;
	index->cap = next.cap;
	index->len = next.len;
	index->max_probe_len = next.max_probe_len;
	index->total_probe_len = next.total_probe_len;

	free(old_ids);
	free(old_hashes);
	free(old_used);
	return 0;
}

static int ensure_insert_capacity(struct stackmap_intern_index *index)
{
	size_t next_len = index->len + 1;

	if (next_len * STACKMAP_INTERN_LOAD_DEN <
	    index->cap * STACKMAP_INTERN_LOAD_NUM)
		return 0;
	if (index->cap > UINT32_MAX / 2)
		return -1;
	return rehash_index(index, index->cap * 2);
}

int stackmap_intern_index_add(struct stackmap_intern_index *index,
			      const void *key, size_t key_len, uint32_t id,
			      stackmap_intern_index_eq_fn eq, void *ctx)
{
	struct stackmap_intern_index_insert insert = { 0 };
	bool found = false;

	if (stackmap_intern_index_prepare_insert(index, key, key_len, eq, ctx,
						 &insert, NULL, &found) != 0)
		return -1;
	if (found)
		return -1;

	return stackmap_intern_index_commit_insert(index, &insert, id);
}

int stackmap_intern_index_prepare_insert(
	struct stackmap_intern_index *index, const void *key, size_t key_len,
	stackmap_intern_index_eq_fn eq, void *ctx,
	struct stackmap_intern_index_insert *insert, uint32_t *id,
	bool *found)
{
	bool slot_found = false;
	size_t slot;
	size_t old_cap;
	uint32_t hash;

	if (!index || !eq || !insert || (!key && key_len > 0))
		return -1;

	hash = hash_bytes(key, key_len);
	slot = find_slot_by_hash(index, hash, key, key_len, eq, ctx,
				 &slot_found);
	if (slot_found) {
		if (id)
			*id = index->ids[slot];
		if (found)
			*found = true;
		return 0;
	}

	old_cap = index->cap;
	if (ensure_insert_capacity(index) != 0)
		return -1;
	if (index->cap != old_cap) {
		slot = find_slot_by_hash(index, hash, key, key_len, eq, ctx,
					 &slot_found);
		if (slot_found) {
			if (id)
				*id = index->ids[slot];
			if (found)
				*found = true;
			return 0;
		}
	}

	insert->slot = slot;
	insert->hash = hash;
	if (found)
		*found = false;
	return 0;
}

int stackmap_intern_index_commit_insert(
	struct stackmap_intern_index *index,
	const struct stackmap_intern_index_insert *insert, uint32_t id)
{
	if (!index || !insert)
		return -1;

	return insert_known_new_at_slot(index, insert->slot, insert->hash, id);
}

size_t stackmap_intern_index_len(const struct stackmap_intern_index *index)
{
	return index ? index->len : 0;
}

size_t stackmap_intern_index_memory_usage(const struct stackmap_intern_index *index)
{
	if (!index)
		return 0;

	return sizeof(*index) +
	       index->cap * (sizeof(*index->ids) + sizeof(*index->hashes) +
			     sizeof(*index->used));
}

int stackmap_intern_index_get_stats(
	const struct stackmap_intern_index *index,
	struct stackmap_intern_index_stats *stats)
{
	if (!index || !stats)
		return -1;

	memset(stats, 0, sizeof(*stats));
	stats->len = index->len;
	stats->cap = index->cap;
	stats->used_bytes =
		index->cap * (sizeof(*index->ids) + sizeof(*index->hashes) +
			      sizeof(*index->used));
	stats->memory_usage = sizeof(*index) + stats->used_bytes;
	stats->load_limit_permille =
		(STACKMAP_INTERN_LOAD_NUM * 1000U) / STACKMAP_INTERN_LOAD_DEN;
	if (index->cap)
		stats->load_factor_permille =
			(uint32_t)(((uint64_t)index->len * 1000U) / index->cap);
	stats->max_probe_len = index->max_probe_len;
	stats->total_probe_len = index->total_probe_len;

	return 0;
}
