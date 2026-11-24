// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef __STACKMAP_INTERN_INDEX_H__
#define __STACKMAP_INTERN_INDEX_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct stackmap_intern_index;

struct stackmap_intern_index_insert {
	size_t slot;
	uint32_t hash;
};

struct stackmap_intern_index_stats {
	size_t len;
	size_t cap;
	size_t memory_usage;
	size_t used_bytes;
	size_t max_probe_len;
	uint64_t total_probe_len;
	uint32_t load_factor_permille;
	uint32_t load_limit_permille;
};

typedef bool (*stackmap_intern_index_eq_fn)(uint32_t id, const void *key,
					    size_t key_len, void *ctx);

struct stackmap_intern_index *stackmap_intern_index_create(void);
void stackmap_intern_index_destroy(struct stackmap_intern_index *index);

bool stackmap_intern_index_find(const struct stackmap_intern_index *index,
				const void *key, size_t key_len,
				stackmap_intern_index_eq_fn eq, void *ctx,
				uint32_t *id);
int stackmap_intern_index_add(struct stackmap_intern_index *index,
			      const void *key, size_t key_len, uint32_t id,
			      stackmap_intern_index_eq_fn eq, void *ctx);
int stackmap_intern_index_prepare_insert(
	struct stackmap_intern_index *index, const void *key, size_t key_len,
	stackmap_intern_index_eq_fn eq, void *ctx,
	struct stackmap_intern_index_insert *insert, uint32_t *id,
	bool *found);
int stackmap_intern_index_commit_insert(
	struct stackmap_intern_index *index,
	const struct stackmap_intern_index_insert *insert, uint32_t id);

size_t stackmap_intern_index_len(const struct stackmap_intern_index *index);
size_t stackmap_intern_index_memory_usage(const struct stackmap_intern_index *index);
int stackmap_intern_index_get_stats(
	const struct stackmap_intern_index *index,
	struct stackmap_intern_index_stats *stats);

#endif
