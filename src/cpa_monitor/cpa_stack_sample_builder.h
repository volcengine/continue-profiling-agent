// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CPA_STACK_SAMPLE_BUILDER_H
#define CPA_STACK_SAMPLE_BUILDER_H

#include "cpa_stack_sample.h"
#include <cpa_bpf/bpf_event.h>
#include <stdbool.h>

/**
 * @file cpa_stack_sample_builder.h
 * @brief Turn a BPF stack event into a stack sample, in one place.
 *
 * This is where a sample gets its process: the off-CPU producer puts the
 * sleeping thread in stack_event::pid and its process in ::cgid, every other
 * producer puts the process in pid.  Samples come from the sample pool and
 * are freed with cpa_sample_free().
 */

/**
 * struct cpa_stack_sample_build_config - what the builder needs to know
 * @offcpu: events come from offcpu_capture
 * @freq: sampling frequency, to weigh IRQ-off samples
 * @kernel_comm: group comm given to kernel threads
 * @lookup_kstack: resolves stack_event::kstack_id when the event carries
 *                 no kernel stack (lite BPF objects), or NULL
 */
struct cpa_stack_sample_build_config {
	bool offcpu;
	unsigned int freq;
	const char *kernel_comm;
	int (*lookup_kstack)(long kstack_id, unsigned long *kstack, int max_level);
};

/**
 * cpa_stack_sample_build_kernel - a sample without a user stack
 * @event: the event
 * @drop: mark the sample dropped under pressure
 * @config: see struct cpa_stack_sample_build_config
 *
 * Return: the sample, or NULL if out of memory.
 */
struct stack_sample *
cpa_stack_sample_build_kernel(const struct stack_event *event, bool drop,
			      const struct cpa_stack_sample_build_config *config);

/**
 * cpa_stack_sample_build_user - a sample with its user stack snapshot
 * @event: the event
 * @stack_content: the @event->stack_size user stack bytes after the event
 * @config: see struct cpa_stack_sample_build_config
 *
 * Return: the sample, or NULL if out of memory.
 */
struct stack_sample *
cpa_stack_sample_build_user(const struct stack_event *event,
			    const char *stack_content,
			    const struct cpa_stack_sample_build_config *config);

#endif
