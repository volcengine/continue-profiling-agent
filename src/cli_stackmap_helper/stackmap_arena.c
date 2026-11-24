// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "stackmap_arena.h"

#include <stdint.h>
#include <stdlib.h>

/* Small maps (oneshot tools, tests) stay small; busy ones settle at 1 MB. */
#define STACKMAP_ARENA_FIRST_CHUNK (4U << 10)
#define STACKMAP_ARENA_MAX_CHUNK (1U << 20)

struct stackmap_arena_chunk {
	struct stackmap_arena_chunk *next;
	size_t cap;
	size_t used;
	size_t last;
	max_align_t data[];
};

struct stackmap_arena {
	struct stackmap_arena_chunk *head;
	size_t next_chunk;
	size_t memory_usage;
};

struct stackmap_arena *stackmap_arena_create(void)
{
	struct stackmap_arena *arena = calloc(1, sizeof(*arena));

	if (!arena)
		return NULL;
	arena->next_chunk = STACKMAP_ARENA_FIRST_CHUNK;
	return arena;
}

void stackmap_arena_destroy(struct stackmap_arena *arena)
{
	struct stackmap_arena_chunk *chunk, *next;

	if (!arena)
		return;
	for (chunk = arena->head; chunk; chunk = next) {
		next = chunk->next;
		free(chunk);
	}
	free(arena);
}

static struct stackmap_arena_chunk *arena_new_chunk(
	struct stackmap_arena *arena, size_t size)
{
	struct stackmap_arena_chunk *chunk;
	size_t cap = arena->next_chunk;

	if (size > cap)
		cap = size;
	if (cap > SIZE_MAX - sizeof(*chunk))
		return NULL;
	chunk = malloc(sizeof(*chunk) + cap);
	if (!chunk)
		return NULL;

	chunk->cap = cap;
	chunk->used = 0;
	chunk->last = 0;
	chunk->next = arena->head;
	arena->head = chunk;
	arena->memory_usage += sizeof(*chunk) + cap;
	if (arena->next_chunk < STACKMAP_ARENA_MAX_CHUNK)
		arena->next_chunk *= 2;
	return chunk;
}

void *stackmap_arena_alloc(struct stackmap_arena *arena, size_t size,
			   size_t align)
{
	struct stackmap_arena_chunk *chunk;
	size_t off;

	if (!arena || !align || (align & (align - 1)) ||
	    align > sizeof(max_align_t))
		return NULL;

	chunk = arena->head;
	if (chunk) {
		off = (chunk->used + align - 1) & ~(align - 1);
		if (off <= chunk->cap && size <= chunk->cap - off)
			goto found;
	}
	chunk = arena_new_chunk(arena, size);
	if (!chunk)
		return NULL;
	off = 0;
found:
	chunk->last = off;
	chunk->used = off + size;
	return (char *)chunk->data + off;
}

void stackmap_arena_unalloc(struct stackmap_arena *arena, void *ptr)
{
	struct stackmap_arena_chunk *chunk = arena ? arena->head : NULL;

	if (chunk && ptr == (char *)chunk->data + chunk->last)
		chunk->used = chunk->last;
}

size_t stackmap_arena_memory_usage(const struct stackmap_arena *arena)
{
	return arena ? sizeof(*arena) + arena->memory_usage : 0;
}
