// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "cpa_frames.h"
#include "cli_output.h"

#include <stdlib.h>
#include <string.h>

void cpa_frames_init(struct cpa_frames *frames)
{
	memset(frames, 0, sizeof(*frames));
}

void cpa_frames_destroy(struct cpa_frames *frames)
{
	free(frames->text);
	free(frames->offsets);
	memset(frames, 0, sizeof(*frames));
}

void cpa_frames_clear(struct cpa_frames *frames)
{
	frames->text_len = 0;
	frames->len = 0;
	frames->last_reverse = 0;
}

static int grow(void **buf, size_t *cap, size_t need, size_t unit)
{
	size_t new_cap = *cap ? *cap : 64;
	void *p;

	if (need <= *cap)
		return 0;
	while (new_cap < need)
		new_cap *= 2;
	p = realloc(*buf, new_cap * unit);
	if (!p)
		return -1;
	*buf = p;
	*cap = new_cap;
	return 0;
}

int cpa_frames_append(struct cpa_frames *frames, const char *frame)
{
	/* cli_stackmap_append() interns at most this much of a frame */
	size_t len = strnlen(frame, CLI_STACKMAP_FRAME_MAX_LEN);
	size_t offsets_cap = frames->cap;

	if (grow((void **)&frames->text, &frames->text_cap,
		 frames->text_len + len + 1, 1) != 0 ||
	    grow((void **)&frames->offsets, &offsets_cap,
		 (size_t)frames->len + 1, sizeof(*frames->offsets)) != 0) {
		CLI_ERROR("cpa frames: out of memory");
		return -1;
	}
	frames->cap = (uint32_t)offsets_cap;
	memcpy(frames->text + frames->text_len, frame, len);
	frames->text[frames->text_len + len] = '\0';
	frames->offsets[frames->len++] = (uint32_t)frames->text_len;
	frames->text_len += len + 1;
	return 0;
}

uint32_t cpa_frames_length(const struct cpa_frames *frames)
{
	return frames->len;
}

/*
 * The text of the dropped frames stays until the next clear: after a
 * reverse it is not the tail of the buffer.  Unlike
 * cli_stackmap_current_reset(), an @index past the end changes nothing.
 */
void cpa_frames_reset(struct cpa_frames *frames, uint32_t index)
{
	if (index > frames->len)
		return;
	frames->len = index;
	frames->last_reverse = index;
}

void cpa_frames_reverse(struct cpa_frames *frames)
{
	uint32_t start = frames->last_reverse;
	uint32_t end;

	if (!frames->len || start >= frames->len)
		return;
	end = frames->len - 1;
	while (start < end) {
		uint32_t tmp = frames->offsets[start];

		frames->offsets[start++] = frames->offsets[end];
		frames->offsets[end--] = tmp;
	}
	frames->last_reverse = frames->len;
}

void cpa_frames_commit(const struct cpa_frames *frames,
			    struct cli_stackmap *map)
{
	for (uint32_t i = 0; i < frames->len; i++)
		cli_stackmap_append(map, frames->text + frames->offsets[i]);
}
