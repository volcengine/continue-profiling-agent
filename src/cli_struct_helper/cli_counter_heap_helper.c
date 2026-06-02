// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include <stdlib.h>
#include <string.h>
#include "cli_counter_heap_helper.h"

struct cli_counter_heap {
	struct cli_counter_heap_entry **heap;
	size_t size;
	size_t capacity;
	struct cli_counter_heap_entry *map;
};

static int ensure_capacity(struct cli_counter_heap *heap)
{
	if (heap->size < heap->capacity)
		return 0;
	size_t new_capacity = heap->capacity ? heap->capacity * 2 : 16;
	struct cli_counter_heap_entry **new_heap = realloc(heap->heap, new_capacity * sizeof(struct cli_counter_heap_entry *));
	if (!new_heap)
		return -1;
	heap->heap = new_heap;
	memset(heap->heap + heap->capacity, 0, (new_capacity - heap->capacity) * sizeof(struct cli_counter_heap_entry *));
	heap->capacity = new_capacity;
	return 0;
}

static void heapify_up(struct cli_counter_heap *heap, size_t index)
{
	while (index) {
		size_t parent = (index - 1) / 2;
		if (heap->heap[index]->value >= heap->heap[parent]->value)
			break;
		struct cli_counter_heap_entry *child = heap->heap[index];
		struct cli_counter_heap_entry *parent_entry = heap->heap[parent];
		heap->heap[index] = parent_entry;
		heap->heap[parent] = child;
		parent_entry->index = index;
		child->index = parent;
		index = parent;
	}
}

static void heapify_down(struct cli_counter_heap *heap, size_t index)
{
	while (1) {
		size_t left = 2 * index + 1;
		if (left >= heap->size)
			break;
		size_t smallest = left;
		size_t right = left + 1;
		if (right < heap->size && heap->heap[right]->value < heap->heap[left]->value)
			smallest = right;
		if (heap->heap[index]->value <= heap->heap[smallest]->value)
			break;
		struct cli_counter_heap_entry *current = heap->heap[index];
		struct cli_counter_heap_entry *child = heap->heap[smallest];
		heap->heap[index] = child;
		heap->heap[smallest] = current;
		child->index = index;
		current->index = smallest;
		index = smallest;
	}
}

struct cli_counter_heap *cli_counter_heap_create(size_t initial_capacity)
{
	struct cli_counter_heap *heap = calloc(1, sizeof(struct cli_counter_heap));
	if (!heap)
		return NULL;
	if (!initial_capacity)
		initial_capacity = 16;
	heap->heap = calloc(initial_capacity, sizeof(struct cli_counter_heap_entry *));
	if (!heap->heap) {
		free(heap);
		return NULL;
	}
	heap->capacity = initial_capacity;
	return heap;
}

void cli_counter_heap_destroy(struct cli_counter_heap *heap, void (*payload_free)(void *))
{
	if (!heap)
		return;
	struct cli_counter_heap_entry *entry;
	struct cli_counter_heap_entry *tmp;
	HASH_ITER (hh, heap->map, entry, tmp) {
		HASH_DEL(heap->map, entry);
		cli_counter_heap_entry_destroy(entry, payload_free);
	}
	free(heap->heap);
	free(heap);
}

struct cli_counter_heap_entry *cli_counter_heap_find(struct cli_counter_heap *heap, int key)
{
	if (!heap)
		return NULL;
	struct cli_counter_heap_entry *entry = NULL;
	HASH_FIND_INT(heap->map, &key, entry);
	return entry;
}

struct cli_counter_heap_entry *cli_counter_heap_insert(struct cli_counter_heap *heap, int key, void *payload, uint64_t initial_value)
{
	if (!heap)
		return NULL;
	struct cli_counter_heap_entry *entry = NULL;
	HASH_FIND_INT(heap->map, &key, entry);
	if (entry)
		return entry;
	if (ensure_capacity(heap))
		return NULL;
	entry = calloc(1, sizeof(struct cli_counter_heap_entry));
	if (!entry)
		return NULL;
	entry->key = key;
	entry->value = initial_value;
	entry->payload = payload;
	entry->index = heap->size;
	heap->heap[heap->size] = entry;
	heap->size++;
	HASH_ADD_INT(heap->map, key, entry);
	heapify_up(heap, entry->index);
	return entry;
}

void cli_counter_heap_increment(struct cli_counter_heap *heap, struct cli_counter_heap_entry *entry, uint64_t delta)
{
	if (!heap || !entry || !delta)
		return;
	entry->value += delta;
	heapify_down(heap, entry->index);
}

struct cli_counter_heap_entry *cli_counter_heap_pop_min(struct cli_counter_heap *heap)
{
	if (!heap || !heap->size)
		return NULL;
	struct cli_counter_heap_entry *min = heap->heap[0];
	HASH_DEL(heap->map, min);
	heap->size--;
	if (!heap->size) {
		heap->heap[0] = NULL;
		return min;
	}
	struct cli_counter_heap_entry *last = heap->heap[heap->size];
	heap->heap[0] = last;
	last->index = 0;
	heap->heap[heap->size] = NULL;
	heapify_down(heap, 0);
	return min;
}

int cli_counter_heap_push_entry(struct cli_counter_heap *heap, struct cli_counter_heap_entry *entry)
{
	if (!heap || !entry)
		return -1;
	if (ensure_capacity(heap))
		return -1;
	entry->index = heap->size;
	heap->heap[heap->size] = entry;
	heap->size++;
	HASH_ADD_INT(heap->map, key, entry);
	heapify_up(heap, entry->index);
	return 0;
}

void cli_counter_heap_entry_destroy(struct cli_counter_heap_entry *entry, void (*payload_free)(void *))
{
	if (!entry)
		return;
	if (payload_free && entry->payload)
		payload_free(entry->payload);
	free(entry);
}

size_t cli_counter_heap_size(struct cli_counter_heap *heap)
{
	if (!heap)
		return 0;
	return heap->size;
}

void cli_counter_heap_update_value(struct cli_counter_heap *heap, struct cli_counter_heap_entry *entry, uint64_t new_value)
{
	if (!heap || !entry)
		return;
	if (new_value == entry->value)
		return;
	uint64_t old_value = entry->value;
	entry->value = new_value;
	if (new_value < old_value)
		heapify_up(heap, entry->index);
	else
		heapify_down(heap, entry->index);
}

void cli_counter_heap_for_each_chunk(struct cli_counter_heap *heap, size_t *cursor, size_t limit, cli_counter_heap_iter_fn fn, void *ctx)
{
	if (!heap || !cursor || !fn || !limit || !heap->size)
		return;
	if (*cursor >= heap->size)
		*cursor = 0;
	size_t chunk = limit;
	if (chunk > heap->size)
		chunk = heap->size;
	struct cli_counter_heap_entry **items = calloc(chunk, sizeof(struct cli_counter_heap_entry *));
	if (!items)
		return;
	size_t idx = *cursor;
	for (size_t i = 0; i < chunk; i++) {
		items[i] = heap->heap[idx];
		idx++;
		if (idx == heap->size)
			idx = 0;
	}
	*cursor = idx;
	for (size_t i = 0; i < chunk; i++)
		if (items[i])
			fn(items[i], ctx);
	free(items);
}
