// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "cpa_stack_sample_builder.h"
#include "cpa_sample_pool.h"

#include <stdio.h>
#include <string.h>

static unsigned long
cpa_stack_sample_count(const struct stack_event *event,
		       const struct cpa_stack_sample_build_config *config)
{
	unsigned long count = config->offcpu ? event->diff_ns : 1;

	if ((event->type & STACK_EVENT_IRQOFF) && config->freq > 0)
		count = (event->diff_ns / (1000 * 1000 * 1000 / config->freq)) + 1;

	return count;
}

/* The process of @event: see struct stack_sample::tgid. */
static int cpa_stack_event_tgid(const struct stack_event *event,
				const struct cpa_stack_sample_build_config *config)
{
	if (config->offcpu)
		return (int)event->cgid;
	return event->pid;
}

static void cpa_stack_sample_copy_kernel_stack(struct stack_sample *sample,
					       const struct stack_event *event)
{
	size_t kstack_level = event->kstack_sz;

	if (kstack_level > MAX_FP_STACK_LEVEL)
		kstack_level = MAX_FP_STACK_LEVEL;

	sample->kstack_fp_level = kstack_level;
	if (kstack_level > 0)
		memcpy(sample->kstack_fp, event->kstack,
		       kstack_level * sizeof(unsigned long));
}

static void cpa_stack_sample_copy_header(struct stack_sample *sample,
					 const struct stack_event *event,
					 const struct cpa_stack_sample_build_config *config)
{
	sample->type = event->type;
	sample->signal = event->signal;
	sample->signal_code = event->signal_code;
	sample->timestamp = event->timestamp;
	sample->user_mode = event->user_mode;
	cpa_stack_sample_copy_kernel_stack(sample, event);
	sample->stack_count = cpa_stack_sample_count(event, config);
	sample->cpu = event->cpu;
	/*
	 * Records keep what they always showed: off CPU, the thread in pid
	 * and the process in the cgroup column.  Only the keying changes.
	 */
	sample->cgid = event->cgid;
	sample->pid = event->pid;
	memcpy(sample->comm, event->comm, TASK_COMM_LEN);
}

struct stack_sample *
cpa_stack_sample_build_kernel(const struct stack_event *event, bool drop,
			      const struct cpa_stack_sample_build_config *config)
{
	struct stack_sample *sample = cpa_sample_zalloc(sizeof(*sample));

	if (!sample)
		return NULL;

	cpa_stack_sample_copy_header(sample, event, config);
	if (drop)
		sample->type |= STACK_EVENT_DROP_BY_PRESSURE;
	if (event->type & STACK_EVENT_KTHREAD)
		snprintf(sample->group_comm, sizeof(sample->group_comm), "%s",
			 config->kernel_comm);
	else
		memcpy(sample->group_comm, event->group_comm, TASK_COMM_LEN);
	stack_sample_set_process(sample, cpa_stack_event_tgid(event, config),
				 event->tid);
	return sample;
}

struct stack_sample *
cpa_stack_sample_build_user(const struct stack_event *event,
			    const char *stack_content,
			    const struct cpa_stack_sample_build_config *config)
{
	struct stack_sample *sample;
	struct gu_stack_info *stack;
	unsigned int fp_size;

	sample = cpa_sample_alloc(sizeof(struct stack_sample) +
				  sizeof(struct gu_stack_info) +
				  event->stack_size + PT_REGS_SIZE);
	if (!sample)
		return NULL;

	memset(sample, 0, sizeof(*sample));
	cpa_stack_sample_copy_header(sample, event, config);
	memcpy(sample->group_comm, event->group_comm, TASK_COMM_LEN);

	stack = (struct gu_stack_info *)(sample + 1);
	memset(stack, 0, sizeof(*stack));
	sample->info = stack;
	stack_sample_set_process(sample, cpa_stack_event_tgid(event, config),
				 event->tid);

	stack->stack_size = event->stack_size;
	stack->unique_id = event->unique_id;
	stack->regs_size = PT_REGS_SIZE;
	stack->stack_data = (uint8_t *)(stack + 1);
	stack->regs = (struct pt_regs *)&stack->stack_data[stack->stack_size];

	fp_size = event->ustack_fp_size;
	if (fp_size > sizeof(event->ustack_fp))
		fp_size = sizeof(event->ustack_fp);
	fp_size -= fp_size % sizeof(uint64_t);
	memcpy(stack->ustack_fp, event->ustack_fp, fp_size);
	stack->ustack_fp_level = fp_size / sizeof(uint64_t);

	memcpy(stack->regs, event->regs, PT_REGS_SIZE);
	memcpy(stack->stack_data, stack_content, stack->stack_size);
	return sample;
}
