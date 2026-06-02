// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef __CLI_INTERVAL_ARRAY_HELPER_H__
#define __CLI_INTERVAL_ARRAY_HELPER_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/**
 * @file cli_interval_array_helper.h
 * @brief Sorted interval array lookup helpers for address-to-object mapping.
 */

/**
 * struct interval_array_item_u32 - 32-bit interval entry.
 * @start: interval start address.
 * @end: interval end address (exclusive).
 * @private: encoded private payload pointer.
 */
struct interval_array_item_u32 {
	uint32_t start;
	uint32_t end;
	void *private;
};

/**
 * struct interval_array_item - 64-bit interval entry.
 * @start: interval start address.
 * @end: interval end address (exclusive).
 * @private: encoded private payload pointer.
 */
struct interval_array_item {
	uint64_t start;
	uint64_t end;
	void *private;
};

/**
 * interval_array_item_u64 - 64-bit interval entry alias.
 */
#define interval_array_item_u64 interval_array_item

enum interval_array_type {
	INTERVAL_ARRAY_TYPE_U32,
	INTERVAL_ARRAY_TYPE_U64,
};

/**
 * struct interval_array - sorted interval lookup table.
 * @items_u32: 32-bit interval storage when @type is U32.
 * @items_u64: 64-bit interval storage when @type is U64.
 * @count: number of intervals.
 * @type: active interval width.
 * @min: cached minimum start address.
 * @max: cached maximum end address.
 */
struct interval_array {
	struct interval_array_item_u32 *items_u32;
	struct interval_array_item_u64 *items_u64;

	int count;
	enum interval_array_type type;

	uint64_t min;
	uint64_t max;
};

/**
 * cli_interval_array_init - build a sorted interval array from entries.
 * @items: input interval entries.
 * @count: number of entries in @items.
 *
 * Return: interval array object or %NULL on failure.
 */
struct interval_array *cli_interval_array_init(struct interval_array_item *items, int count);

/**
 * cli_interval_array_destroy - free interval array internals.
 * @array: interval array to destroy.
 */
void cli_interval_array_destroy(struct interval_array *array);

/**
 * cli_interval_array_search - find interval covering @addr.
 * @array: interval array to query.
 * @addr: target address.
 * @item: output interval copy.
 *
 * Return: 0 on success, negative on failure.
 */
int cli_interval_array_search(struct interval_array *array, uint64_t addr, struct interval_array_item *item);

/**
 * cli_interval_array_search_set_no_free - search interval and keep no-free mark.
 * @array: interval array to query.
 * @addr: target address.
 * @item: output interval copy.
 *
 * Return: 0 on success, negative on failure.
 */
int cli_interval_array_search_set_no_free(struct interval_array *array, uint64_t addr, struct interval_array_item *item);

/**
 * mark_interval_array_pointer_no_free - set internal no-free bit for payload.
 * @ptr_value: encoded pointer value.
 *
 * Return: encoded pointer with no-free bit set.
 */
static inline uint64_t mark_interval_array_pointer_no_free(uint64_t ptr_value)
{
	ptr_value |= (1ULL << 63);
	return ptr_value;
}

/**
 * get_interval_array_pointer - decode encoded payload pointer.
 * @ptr_value: encoded pointer value.
 * @no_free: optional output that receives no-free marker status.
 *
 * Return: decoded pointer with marker bit cleared.
 */
static inline void *get_interval_array_pointer(uint64_t ptr_value, bool *no_free)
{
	bool is_marked = (ptr_value & (1ULL << 63)) != 0;

	if (no_free)
		*no_free = is_marked;

	ptr_value &= ~(1ULL << 63);
	return (void *)ptr_value;
}

/**
 * private_process_p - callback used to visit private pointers.
 * @pointer: decoded payload pointer.
 * @ctx: user data.
 */
typedef void (*private_process_p)(void *pointer, void *ctx);

/**
 * cli_interval_array_for_each_private - visit each payload pointer.
 * @array: interval array to walk.
 * @func: callback for each payload pointer.
 * @ctx: user context for @func.
 */
void cli_interval_array_for_each_private(struct interval_array *array, private_process_p func, void *ctx);

#endif /* __CLI_INTERVAL_ARRAY_HELPER_H__ */
