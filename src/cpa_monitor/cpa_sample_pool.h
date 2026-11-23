// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CPA_SAMPLE_POOL_H
#define CPA_SAMPLE_POOL_H

#include <stddef.h>

/**
 * @file cpa_sample_pool.h
 * @brief Free list of sample buffers, so the capture path does not call
 *        malloc() and free() for every sample.
 *
 * A freed buffer is kept, up to the pool's limit, and handed to the next
 * allocation it is large enough for (first fit).  Buffers allocated before
 * cpa_sample_pool_init() or after cpa_sample_pool_destroy() go straight to
 * malloc() and free().
 */

/** cpa_sample_pool_default_limit - buffers kept by default: 4 per CPU */
unsigned int cpa_sample_pool_default_limit(void);
/** cpa_sample_pool_init - start keeping up to @max_cached freed buffers */
int cpa_sample_pool_init(unsigned int max_cached);
/** cpa_sample_pool_destroy - free every kept buffer and stop keeping them */
void cpa_sample_pool_destroy(void);

/** cpa_sample_alloc - a buffer of at least @size bytes, uninitialized */
void *cpa_sample_alloc(size_t size);
/** cpa_sample_zalloc - a buffer of @size zeroed bytes */
void *cpa_sample_zalloc(size_t size);
/** cpa_sample_free - give back a buffer from cpa_sample_alloc/zalloc() */
void cpa_sample_free(void *ptr);

#endif
