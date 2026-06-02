// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CPA_UNWIND_STATE_H
#define CPA_UNWIND_STATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <gunwinder/unwinder_types.h>

/*
 * x86 pt_regs is 168 bytes and arm64 pt_regs is 272 bytes in libgunwinder.
 * Keep the snapshot on stack to avoid a malloc/free pair on every sample.
 */
#define CPA_UNWIND_REGS_SNAPSHOT_SIZE 512U

struct cpa_unwind_state {
	uint64_t flags;
	uint32_t regs_size;
	void *regs;
};

static inline bool cpa_unwind_state_save(struct cpa_unwind_state *state, const struct gu_stack_info *info, void *regs_buf, size_t regs_buf_size)
{
	if (!state || !info)
		return false;

	state->flags = info->flags;
	state->regs_size = info->regs_size;
	state->regs = regs_buf;

	if (info->regs_size == 0)
		return true;
	if (!info->regs || !regs_buf || regs_buf_size < info->regs_size)
		return false;

	memcpy(regs_buf, info->regs, info->regs_size);
	return true;
}

static inline bool cpa_unwind_state_restore(struct gu_stack_info *info, const struct cpa_unwind_state *state)
{
	if (!info || !state)
		return false;

	if (state->regs_size != 0) {
		if (!info->regs || !state->regs || info->regs_size != state->regs_size)
			return false;
		memcpy(info->regs, state->regs, state->regs_size);
	}

	info->flags = state->flags;
	return true;
}

#endif /* CPA_UNWIND_STATE_H */
