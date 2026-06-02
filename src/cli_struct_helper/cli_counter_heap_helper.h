// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef __CLI_COUNTER_HEAP_HELPER_H__
#define __CLI_COUNTER_HEAP_HELPER_H__

#include <stddef.h>
#include <stdint.h>
#include "uthash.h"

/**
 * @file cli_counter_heap_helper.h
 * @brief Min-heap plus hash index for top-N counter style workloads.
 */

/**
 * struct cli_counter_heap_entry - one heap node plus hash entry.
 * @key: external lookup key
 * @value: sortable counter value
 * @payload: caller-owned payload associated with @key
 * @index: current heap slot
 * @hh: uthash linkage
 */
struct cli_counter_heap_entry {
	int key;
	uint64_t value;
	void *payload;
	size_t index;
	UT_hash_handle hh;
};

/**
 * struct cli_counter_heap - opaque min-heap object.
 */
struct cli_counter_heap;

/**
 * cli_counter_heap_create - allocate a heap with given initial capacity.
 * @initial_capacity: preferred capacity; zero means default 16.
 *
 * Return: initialized heap object or %NULL on failure.
 */
struct cli_counter_heap *cli_counter_heap_create(size_t initial_capacity);

/**
 * cli_counter_heap_destroy - free heap and all entries.
 * @heap: heap instance.
 * @payload_free: optional payload destructor.
 */
void cli_counter_heap_destroy(struct cli_counter_heap *heap, void (*payload_free)(void *));

/**
 * cli_counter_heap_find - find an entry by key.
 * @heap: heap instance.
 * @key: entry key to search.
 *
 * Return: matching entry or %NULL if absent.
 */
struct cli_counter_heap_entry *cli_counter_heap_find(struct cli_counter_heap *heap, int key);

/**
 * cli_counter_heap_insert - insert one entry.
 * @heap: heap instance.
 * @key: entry key.
 * @payload: payload to associate.
 * @initial_value: initial counter value.
 *
 * Return: new/existing entry, %NULL on allocation failure.
 */
struct cli_counter_heap_entry *cli_counter_heap_insert(struct cli_counter_heap *heap, int key, void *payload, uint64_t initial_value);

/**
 * cli_counter_heap_increment - add @delta to entry value and reorder heap.
 * @heap: heap instance.
 * @entry: entry to update.
 * @delta: increment amount.
 */
void cli_counter_heap_increment(struct cli_counter_heap *heap, struct cli_counter_heap_entry *entry, uint64_t delta);

/**
 * cli_counter_heap_pop_min - remove and return minimum value entry.
 * @heap: heap instance.
 *
 * Return: minimum entry or %NULL if empty.
 */
struct cli_counter_heap_entry *cli_counter_heap_pop_min(struct cli_counter_heap *heap);

/**
 * cli_counter_heap_push_entry - push an existing entry into the heap.
 * @heap: heap instance.
 * @entry: detached entry.
 *
 * Return: 0 on success, negative on failure.
 */
int cli_counter_heap_push_entry(struct cli_counter_heap *heap, struct cli_counter_heap_entry *entry);

/**
 * cli_counter_heap_entry_destroy - destroy a detached heap entry.
 * @entry: entry to destroy.
 * @payload_free: optional payload destructor.
 */
void cli_counter_heap_entry_destroy(struct cli_counter_heap_entry *entry, void (*payload_free)(void *));

/**
 * cli_counter_heap_size - return live entry count.
 * @heap: heap instance.
 *
 * Return: number of live entries.
 */
size_t cli_counter_heap_size(struct cli_counter_heap *heap);

/**
 * cli_counter_heap_update_value - replace @entry value and restore order.
 * @heap: heap instance.
 * @entry: entry to update.
 * @new_value: new counter value.
 */
void cli_counter_heap_update_value(struct cli_counter_heap *heap, struct cli_counter_heap_entry *entry, uint64_t new_value);

/**
 * cli_counter_heap_iter_fn - callback for iterating heap entries.
 * @entry: visited entry.
 * @ctx: user context.
 */
typedef void (*cli_counter_heap_iter_fn)(struct cli_counter_heap_entry *entry, void *ctx);

/**
 * cli_counter_heap_for_each_chunk - iterate a bounded chunk of entries.
 * @heap: heap instance.
 * @cursor: in/out cursor for incremental traversal.
 * @limit: maximum number of entries to visit.
 * @fn: callback function.
 * @ctx: user context for @fn.
 */
void cli_counter_heap_for_each_chunk(struct cli_counter_heap *heap, size_t *cursor, size_t limit, cli_counter_heap_iter_fn fn, void *ctx);

#endif /* __CLI_COUNTER_HEAP_HELPER_H__ */
