// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: ByteDance Inc

#ifndef __STACKMAP_COUNT_TABLE_H__
#define __STACKMAP_COUNT_TABLE_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct stackmap_count_item {
	uint32_t ids_id;
	uint64_t count;
};

struct stackmap_count_table;

typedef int (*stackmap_count_iter_fn)(uint32_t ids_id, uint64_t count,
				      void *ctx);

struct stackmap_count_table *stackmap_count_table_create(void);
void stackmap_count_table_destroy(struct stackmap_count_table *table);

int stackmap_count_table_add(struct stackmap_count_table *table,
			     uint32_t ids_id, uint64_t count);
bool stackmap_count_table_get(const struct stackmap_count_table *table,
			      uint32_t ids_id, uint64_t *count);
size_t stackmap_count_table_len(const struct stackmap_count_table *table);
size_t stackmap_count_table_memory_usage(
	const struct stackmap_count_table *table);

int stackmap_count_table_for_each(const struct stackmap_count_table *table,
				  stackmap_count_iter_fn fn, void *ctx);
int stackmap_count_table_take_items(struct stackmap_count_table *table,
				    bool nonzero_only,
				    struct stackmap_count_item **items,
				    size_t *len);
void stackmap_count_table_reset(struct stackmap_count_table *table);

#endif
