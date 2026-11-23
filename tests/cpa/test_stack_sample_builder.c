// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

/*
 * Unit test of the sample pool and the stack sample builder: which task a
 * sample shows, which process it is keyed by, and what libgunwinder is told.
 */

#include "cpa_sample_pool.h"
#include "cpa_stack_sample_builder.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond, ...)                                     \
	do {                                                 \
		if (!(cond)) {                               \
			fprintf(stderr, "%s:%d: ", __FILE__, __LINE__); \
			fprintf(stderr, __VA_ARGS__);        \
			fputc('\n', stderr);                 \
			return 1;                            \
		}                                            \
	} while (0)

static struct stack_event *make_event(unsigned int stack_size)
{
	struct stack_event *e = calloc(1, sizeof(*e) + stack_size);

	e->pid = 100;
	e->tid = 101;
	e->cgid = 7777;
	e->timestamp = 123456789;
	e->cpu = 3;
	e->unique_id = 4242;
	e->stack_size = stack_size;
	e->ustack_fp[0] = 0x1000;
	e->ustack_fp[1] = 0x2000;
	e->ustack_fp_size = 2 * sizeof(e->ustack_fp[0]);
	e->kstack[0] = 0xffffffff81000000UL;
	e->kstack_sz = 1;
	strcpy(e->comm, "worker");
	strcpy(e->group_comm, "app");
	for (unsigned int i = 0; i < stack_size; i++)
		((unsigned char *)(e + 1))[i] = (unsigned char)i;
	return e;
}

static int test_pool(void)
{
	unsigned char *small, *large, *reused, *zeroed;

	CHECK(cpa_sample_pool_init(4) == 0, "init");
	small = cpa_sample_alloc(128);
	large = cpa_sample_alloc(256);
	CHECK(small && large, "alloc");
	cpa_sample_free(small);
	cpa_sample_free(large);
	reused = cpa_sample_alloc(64);
	CHECK(reused == large, "pool did not hand out the first fitting block");
	memset(reused, 0xff, 64);
	cpa_sample_free(reused);
	zeroed = cpa_sample_zalloc(64);
	CHECK(zeroed, "zalloc");
	for (int i = 0; i < 64; i++)
		CHECK(zeroed[i] == 0, "zalloc returned dirty memory");
	cpa_sample_free(zeroed);
	cpa_sample_pool_destroy();
	/* after destroy, buffers go straight to malloc() and free() */
	small = cpa_sample_alloc(32);
	CHECK(small, "alloc after destroy");
	cpa_sample_free(small);
	return 0;
}

static int test_on_cpu(void)
{
	const struct cpa_stack_sample_build_config cfg = { .freq = 99, .kernel_comm = "[kernel]" };
	struct stack_event *e = make_event(64);
	struct stack_sample *s = cpa_stack_sample_build_user(e, (const char *)(e + 1), &cfg);

	CHECK(s && s->info, "build");
	CHECK(s->pid == 100 && s->tgid == 100, "pid %d tgid %d", s->pid, s->tgid);
	CHECK(s->info->pid == 100 && s->info->tid == 101, "unwinder pid %d tid %d",
	      s->info->pid, s->info->tid);
	CHECK(s->cgid == 7777, "cgid");
	CHECK(s->info->unique_id == 4242, "unique_id");
	CHECK(s->info->ustack_fp_level == 2 && s->info->ustack_fp[1] == 0x2000, "fp");
	CHECK(s->info->stack_size == 64 && s->info->stack_data[63] == 63, "stack copy");
	CHECK(s->info->flags == 0, "unwind flags must start clear");
	CHECK(s->kstack_fp_level == 1, "kstack");
	CHECK(s->stack_count == 1, "count");
	cpa_sample_free(s);
	free(e);
	return 0;
}

static int test_off_cpu(void)
{
	const struct cpa_stack_sample_build_config cfg = { .offcpu = true, .freq = 99,
							   .kernel_comm = "[kernel]" };
	struct stack_event *e = make_event(32);
	struct stack_sample *s;

	/* off CPU: the thread in pid, the process in cgid */
	e->pid = 205;
	e->tid = 205;
	e->cgid = 200;
	e->diff_ns = 5000000;
	s = cpa_stack_sample_build_user(e, (const char *)(e + 1), &cfg);
	CHECK(s, "build");
	CHECK(s->pid == 205, "record must still show the thread, got %d", s->pid);
	CHECK(s->tgid == 200, "sample must be keyed by the process, got %d", s->tgid);
	CHECK(s->info->pid == 200 && s->info->tid == 205,
	      "unwinder must get the process and the thread: %d %d", s->info->pid, s->info->tid);
	CHECK(s->cgid == 200, "record keeps the process in the cgroup column");
	CHECK(s->stack_count == 5000000, "off-CPU weight is the sleep time");
	cpa_sample_free(s);
	free(e);
	return 0;
}

static int test_kernel(void)
{
	const struct cpa_stack_sample_build_config cfg = { .freq = 100, .kernel_comm = "[kernel]" };
	struct stack_event *e = make_event(0);
	struct stack_sample *s;

	e->type = STACK_EVENT_KTHREAD | STACK_EVENT_IRQOFF;
	e->diff_ns = 35000000;	/* 3.5 sampling periods at 100 Hz */
	s = cpa_stack_sample_build_kernel(e, false, &cfg);
	CHECK(s && !s->info, "kernel sample has no user snapshot");
	CHECK(strcmp(s->group_comm, "[kernel]") == 0, "kthread group comm");
	CHECK(s->tgid == 100, "tgid");
	CHECK(s->stack_count == 4, "IRQ-off weight %lu", s->stack_count);
	cpa_sample_free(s);

	e->type = 0;
	s = cpa_stack_sample_build_kernel(e, true, &cfg);
	CHECK(s && (s->type & STACK_EVENT_DROP_BY_PRESSURE), "drop mark");
	CHECK(strcmp(s->group_comm, "app") == 0, "user task keeps its group comm");
	cpa_sample_free(s);
	free(e);
	return 0;
}

int main(void)
{
	if (test_pool() || test_on_cpu() || test_off_cpu() || test_kernel())
		return 1;
	puts("stack sample builder ok");
	return 0;
}
