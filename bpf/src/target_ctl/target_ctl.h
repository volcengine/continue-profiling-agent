// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CPA_BPF_TARGET_CTL_H
#define CPA_BPF_TARGET_CTL_H

#include <stdbool.h>
#include <stdint.h>
#include <bpf/libbpf.h>
#include "bpf_event_poll.h"
#include <cpa_bpf/target_filter.h>

/* Which birth hooks target_ctl_start() managed to attach. */
struct target_ctl_hooks {
	bool exec;		/* rule matches at exec */
	bool exec_tracepoint;	/* via sched_process_exec (with t0 sample),
				 * otherwise via kretprobe/setup_new_exec */
	bool fork;		/* wake_up_new_task: children of selected processes */
};

/*
 * Publish @rules, start delivering struct target_event notifications to @fn
 * and attach the birth hooks.  A hook that cannot be attached is reported in
 * @hooks rather than failing the call; the caller decides whether the
 * selection can be honoured without it.  Returns a negative errno only when
 * the rules or the event stream cannot be set up.
 */
int target_ctl_start(const struct target_rules *rules, bpf_event_process_fn fn,
		     struct target_ctl_hooks *hooks);

/* Republish @rules (e.g. to end the scan fence). */
int target_ctl_update_rules(const struct target_rules *rules);

/* Owner fds (valid after the module is initialised). */
int target_ctl_pids_fd(void);
int target_ctl_latch_fd(void);

/* Install the stack_capture t0 program into the exec tail-call slot. */
int target_ctl_set_t0_prog(int prog_fd);

/*
 * Adopt the owner's target_pids in a consumer object between open and load.
 *
 * Guard 2 of the sharing contract: compare the consumer's compiled definition
 * with the owner map before calling bpf_map__reuse_fd(), because libbpf copies
 * the owner's definition over the consumer's without any compatibility check.
 * Returns 0 when the map is shared, -EXDEV when the definitions differ (the
 * consumer keeps a private map and the controller refuses to start), or
 * another negative errno.
 *
 * @owner_fd < 0 means "no dynamic targets": the private map is shrunk to one
 * entry so the unused definition does not pin memory.
 */
int target_ctl_adopt_pids_map(struct bpf_map *consumer, int owner_fd);

/* Kernel map id of @fd (Guard 4: prove two fds reference one map). */
uint32_t target_ctl_map_id(int fd);

/* Keep capture objects on private maps (testing / CPA_TARGET_FORCE_PRIVATE_MAP). */
bool target_ctl_force_private_map(void);

#endif
