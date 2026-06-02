// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "cli_interval_array_helper.h"

static int compare_intervals(const void *a, const void *b)
{
	struct interval_array_item *itemA = (struct interval_array_item *)a;
	struct interval_array_item *itemB = (struct interval_array_item *)b;
	return (itemA->start > itemB->start) - (itemA->start < itemB->start);
}

struct interval_array *cli_interval_array_init(struct interval_array_item *items, int count)
{
	struct interval_array *array;

	if (count == 0)
		return NULL;

	array = (struct interval_array *)calloc(1, sizeof(struct interval_array));
	if (!array)
		return NULL;

	qsort(items, count, sizeof(struct interval_array_item), compare_intervals);

	for (int i = 0; i < count - 1; i++)
		if (items[i].end == 0)
			items[i].end = items[i + 1].start;

	if (items[count - 1].end == 0) {
		if (items[count - 1].start < UINT32_MAX)
			items[count - 1].end = UINT32_MAX - 1;
		else
			items[count - 1].end = UINT64_MAX - 1;
	}

	if (items[count - 1].end < UINT32_MAX) {
		array->type = INTERVAL_ARRAY_TYPE_U32;
		array->items_u32 = calloc(count, sizeof(struct interval_array_item_u32));
		if (!array->items_u32)
			goto free_array;

		for (int i = 0; i < count; i++) {
			array->items_u32[i].start = (uint32_t)items[i].start;
			array->items_u32[i].end = (uint32_t)items[i].end;
			array->items_u32[i].private = items[i].private;
		}

		array->min = array->items_u32[0].start;
		array->max = array->items_u32[count - 1].end;

	} else {
		array->type = INTERVAL_ARRAY_TYPE_U64;
		array->items_u64 = calloc(count, sizeof(struct interval_array_item_u64));
		if (!array->items_u64)
			goto free_array;

		memcpy(array->items_u64, items, count * sizeof(struct interval_array_item_u64));
		array->min = array->items_u64[0].start;
		array->max = array->items_u64[count - 1].end;
	}

	array->count = count;

	return array;

free_array:

	if (array) {
		if (array->items_u32)
			free(array->items_u32);
		if (array->items_u64)
			free(array->items_u64);
		free(array);
	}
	return NULL;
}

void cli_interval_array_for_each_private(struct interval_array *array, private_process_p func, void *ctx)
{
	if (!array)
		return;

	void *pointer;

	if (array->items_u32) {
		for (int i = 0; i < array->count; i++) {
			pointer = array->items_u32[i].private;
			if (pointer) {
				pointer = (void *)get_interval_array_pointer((uint64_t)pointer, NULL);
				func(pointer, ctx);
			}
		}
	}

	if (array->items_u64) {
		for (int i = 0; i < array->count; i++) {
			pointer = array->items_u64[i].private;
			if (pointer) {
				pointer = (void *)get_interval_array_pointer((uint64_t)pointer, NULL);
				func(pointer, ctx);
			}
		}
	}
}

bool test_print = false;

void cli_interval_array_destroy(struct interval_array *array)
{
	if (!array)
		return;

	bool no_free;
	void *pointer;

	if (array->items_u32) {
		for (int i = 0; i < array->count; i++) {
			pointer = array->items_u32[i].private;
			if (pointer) {
				pointer = (void *)get_interval_array_pointer((uint64_t)pointer, &no_free);
				if (!no_free)
					free(pointer);
			}
		}
		free(array->items_u32);
	}

	if (array->items_u64) {
		for (int i = 0; i < array->count; i++) {
			pointer = array->items_u64[i].private;
			if (pointer) {
				pointer = (void *)get_interval_array_pointer((uint64_t)pointer, &no_free);
				if (!no_free)
					free(pointer);
			}
		}
		free(array->items_u64);
	}

	free(array);
}

int __cli_interval_array_search(struct interval_array *array, uint64_t addr, struct interval_array_item *item, bool set_no_free)
{
	int left = 0;
	int right = array->count - 1;

	memset(item, 0, sizeof(struct interval_array_item));

	if (!array || (!array->items_u32 && !array->items_u64))
		return -1;

	if (addr < array->min || addr > array->max)
		return -1;

	bool no_free;

	if (array->type == INTERVAL_ARRAY_TYPE_U32) {
		while (left <= right) {
			int mid = left + (right - left) / 2;

			if (addr >= array->items_u32[mid].start && addr < array->items_u32[mid].end) {
				item->start = array->items_u32[mid].start;
				item->end = array->items_u32[mid].end;
				item->private = get_interval_array_pointer((uint64_t)array->items_u32[mid].private, &no_free);
				if (set_no_free && !no_free)
					array->items_u32[mid].private = (void *)mark_interval_array_pointer_no_free((uint64_t)array->items_u32[mid].private);
				return mid;
			} else if (addr < array->items_u32[mid].start) {
				right = mid - 1;
			} else {
				left = mid + 1;
			}
		}
	}

	if (array->type == INTERVAL_ARRAY_TYPE_U64) {
		while (left <= right) {
			int mid = left + (right - left) / 2;

			if (addr >= array->items_u64[mid].start && addr < array->items_u64[mid].end) {
				item->start = array->items_u64[mid].start;
				item->end = array->items_u64[mid].end;
				item->private = get_interval_array_pointer((uint64_t)array->items_u64[mid].private, &no_free);
				if (set_no_free && !no_free)
					array->items_u64[mid].private = (void *)mark_interval_array_pointer_no_free((uint64_t)array->items_u64[mid].private);
				return mid;
			} else if (addr < array->items_u64[mid].start) {
				right = mid - 1;
			} else {
				left = mid + 1;
			}
		}
	}

	return -1;
}

int cli_interval_array_search(struct interval_array *array, uint64_t addr, struct interval_array_item *item)
{
	return __cli_interval_array_search(array, addr, item, false);
}

int cli_interval_array_search_set_no_free(struct interval_array *array, uint64_t addr, struct interval_array_item *item)
{
	return __cli_interval_array_search(array, addr, item, true);
}
