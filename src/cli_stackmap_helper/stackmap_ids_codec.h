// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef __STACKMAP_IDS_CODEC_H__
#define __STACKMAP_IDS_CODEC_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * An interned stack is kept as a record of
 *
 *	varint(payload bytes) payload
 *
 * where the payload has one varint per frame: the zigzag of the difference
 * to the previous frame's string id (the first one to 0).  Ids are
 * allocated in the order frames are first seen, so neighbouring frames of a
 * stack are mostly close ids: a real store needs 1.5 bytes per frame
 * instead of 4.  The encoding is lossless and unique, so comparing payloads
 * is comparing stacks.
 */

/* Worst case of one u32 frame delta (33 significant bits). */
#define STACKMAP_IDS_VARINT_MAX 5U

static inline size_t stackmap_ids_put_varint(uint8_t *out, uint64_t value)
{
	size_t len = 0;

	while (value >= 0x80) {
		out[len++] = (uint8_t)value | 0x80;
		value >>= 7;
	}
	out[len++] = (uint8_t)value;
	return len;
}

static inline size_t stackmap_ids_varint_len(uint64_t value)
{
	size_t len = 1;

	while (value >= 0x80) {
		value >>= 7;
		len++;
	}
	return len;
}

static inline const uint8_t *stackmap_ids_get_varint(const uint8_t *in,
						     uint64_t *value)
{
	uint64_t result = 0;
	unsigned int shift = 0;

	while (*in & 0x80) {
		result |= (uint64_t)(*in++ & 0x7f) << shift;
		shift += 7;
	}
	*value = result | (uint64_t)*in++ << shift;
	return in;
}

/* @out holds at least @len * STACKMAP_IDS_VARINT_MAX bytes. */
static inline size_t stackmap_ids_encode(uint8_t *out, const uint32_t *ids,
					 uint32_t len)
{
	uint32_t prev = 0;
	size_t pos = 0;

	for (uint32_t i = 0; i < len; i++) {
		int64_t delta = (int64_t)ids[i] - prev;

		pos += stackmap_ids_put_varint(
			out + pos,
			((uint64_t)delta << 1) ^ (uint64_t)(delta >> 63));
		prev = ids[i];
	}
	return pos;
}

struct stackmap_ids_iter {
	const uint8_t *pos;
	const uint8_t *end;
	uint32_t prev;
};

static inline void stackmap_ids_iter_init(struct stackmap_ids_iter *it,
					  const uint8_t *record)
{
	uint64_t payload_len = 0;

	it->pos = it->end = record;
	it->prev = 0;
	if (!record)
		return;
	it->pos = stackmap_ids_get_varint(record, &payload_len);
	it->end = it->pos + payload_len;
}

static inline bool stackmap_ids_iter_next(struct stackmap_ids_iter *it,
					  uint32_t *id)
{
	uint64_t zigzag;

	if (it->pos >= it->end)
		return false;
	it->pos = stackmap_ids_get_varint(it->pos, &zigzag);
	it->prev += (uint32_t)((zigzag >> 1) ^ -(zigzag & 1));
	*id = it->prev;
	return true;
}

/* The payload of @record and its length, the key the ids index hashes. */
static inline const uint8_t *stackmap_ids_payload(const uint8_t *record,
						  size_t *len)
{
	uint64_t payload_len;
	const uint8_t *payload = stackmap_ids_get_varint(record, &payload_len);

	*len = (size_t)payload_len;
	return payload;
}

#endif
