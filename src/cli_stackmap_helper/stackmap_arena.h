// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef __STACKMAP_ARENA_H__
#define __STACKMAP_ARENA_H__

#include <stddef.h>

/*
 * Append-only storage for interned records.  A stack map never frees one
 * record by itself (ids stay valid for the whole store directory), so the
 * records are packed into chunks instead of one malloc() each: no allocator
 * header or size-class rounding per record.  Chunks never move, so a record
 * pointer stays valid until stackmap_arena_destroy().
 */
struct stackmap_arena;

struct stackmap_arena *stackmap_arena_create(void);
void stackmap_arena_destroy(struct stackmap_arena *arena);

/* @align must be a power of two no larger than the alignment of malloc(). */
void *stackmap_arena_alloc(struct stackmap_arena *arena, size_t size,
			   size_t align);
/* Give back @ptr if it is the latest allocation; otherwise it stays used. */
void stackmap_arena_unalloc(struct stackmap_arena *arena, void *ptr);

/* Bytes of all chunks, what the arena holds from the allocator. */
size_t stackmap_arena_memory_usage(const struct stackmap_arena *arena);

#endif
