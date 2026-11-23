// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CPA_FRAMES_H
#define CPA_FRAMES_H

#include "cli_stackmap.h"

#include <stdint.h>

/*
 * The frames of one sample, built by one unwind worker without any lock and
 * then committed to the shared trace stack map in one short critical
 * section.  It mirrors the stack map's current entry: append, length,
 * reset to an index, and reverse what was appended since the last reverse,
 * so the commit appends the very sequence the map would have built.  Its
 * frame cap is CLI_STACKMAP_FRAME_MAX_LEN; a change to the map's current
 * entry semantics (cli_stackmap.h) is a change here too.
 */
struct cpa_frames {
	char *text;		/* NUL-terminated frames, back to back */
	size_t text_len;
	size_t text_cap;
	uint32_t *offsets;	/* frame i starts at text + offsets[i] */
	uint32_t len;
	uint32_t cap;
	uint32_t last_reverse;
};

void cpa_frames_init(struct cpa_frames *frames);
void cpa_frames_destroy(struct cpa_frames *frames);
/* Start a new sample; keeps the buffers. */
void cpa_frames_clear(struct cpa_frames *frames);
int cpa_frames_append(struct cpa_frames *frames, const char *frame);
uint32_t cpa_frames_length(const struct cpa_frames *frames);
/* Drop the frames from @index on, like cli_stackmap_current_reset(). */
void cpa_frames_reset(struct cpa_frames *frames, uint32_t index);
/* Like cli_stackmap_entry_reverse_ids(). */
void cpa_frames_reverse(struct cpa_frames *frames);
/* Append every frame, in order, to @map's current entry (caller holds it). */
void cpa_frames_commit(const struct cpa_frames *frames,
			    struct cli_stackmap *map);

#endif
