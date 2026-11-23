// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "cpa_sample_pool.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysinfo.h>

struct cpa_sample_pool_block {
	struct cpa_sample_pool_block *next;
	size_t capacity;
	long double align;
};

struct cpa_sample_pool {
	pthread_mutex_t lock;
	struct cpa_sample_pool_block *free_list;
	unsigned int cached_count;
	unsigned int max_cached;
	bool initialized;
};

static struct cpa_sample_pool sample_pool = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
};

unsigned int cpa_sample_pool_default_limit(void)
{
	int cpus = get_nprocs();

	if (cpus <= 0)
		cpus = 1;
	return (unsigned int)cpus * 4;
}

int cpa_sample_pool_init(unsigned int max_cached)
{
	pthread_mutex_lock(&sample_pool.lock);
	if (sample_pool.initialized) {
		sample_pool.max_cached = max_cached;
		pthread_mutex_unlock(&sample_pool.lock);
		return 0;
	}

	sample_pool.free_list = NULL;
	sample_pool.cached_count = 0;
	sample_pool.max_cached = max_cached;
	sample_pool.initialized = true;
	pthread_mutex_unlock(&sample_pool.lock);
	return 0;
}

void cpa_sample_pool_destroy(void)
{
	struct cpa_sample_pool_block *block;

	pthread_mutex_lock(&sample_pool.lock);
	block = sample_pool.free_list;
	sample_pool.free_list = NULL;
	sample_pool.cached_count = 0;
	sample_pool.max_cached = 0;
	sample_pool.initialized = false;
	pthread_mutex_unlock(&sample_pool.lock);

	while (block) {
		struct cpa_sample_pool_block *next = block->next;
		free(block);
		block = next;
	}
}

void *cpa_sample_alloc(size_t size)
{
	struct cpa_sample_pool_block **prev;
	struct cpa_sample_pool_block *block;

	if (size == 0)
		size = 1;

	pthread_mutex_lock(&sample_pool.lock);
	if (sample_pool.initialized) {
		prev = &sample_pool.free_list;
		while (*prev) {
			block = *prev;
			if (block->capacity >= size) {
				*prev = block->next;
				sample_pool.cached_count--;
				pthread_mutex_unlock(&sample_pool.lock);
				return block + 1;
			}
			prev = &(*prev)->next;
		}
	}
	pthread_mutex_unlock(&sample_pool.lock);

	block = malloc(sizeof(*block) + size);
	if (!block)
		return NULL;
	block->capacity = size;
	block->next = NULL;
	return block + 1;
}

void *cpa_sample_zalloc(size_t size)
{
	void *ptr = cpa_sample_alloc(size);

	if (ptr)
		memset(ptr, 0, size);
	return ptr;
}

void cpa_sample_free(void *ptr)
{
	struct cpa_sample_pool_block *block;

	if (!ptr)
		return;

	block = ((struct cpa_sample_pool_block *)ptr) - 1;

	pthread_mutex_lock(&sample_pool.lock);
	if (sample_pool.initialized &&
	    sample_pool.cached_count < sample_pool.max_cached) {
		block->next = sample_pool.free_list;
		sample_pool.free_list = block;
		sample_pool.cached_count++;
		pthread_mutex_unlock(&sample_pool.lock);
		return;
	}
	pthread_mutex_unlock(&sample_pool.lock);

	free(block);
}
