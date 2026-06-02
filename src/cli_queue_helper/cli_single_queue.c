// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include "cli_single_queue.h"

static int is_power_of_two(unsigned int x)
{
	return (x != 0) && ((x & (x - 1)) == 0);
}

void queue_init(struct single_queue *q, unsigned int size)
{
	q->size = size;
	q->is_power_of_two = is_power_of_two(size);

	if (q->is_power_of_two) {
		q->mask = size - 1;
	} else {
		q->mask = 0;
	}

	q->data = (void **)malloc(sizeof(void *) * size);
	atomic_init(&q->head, 0);
	atomic_init(&q->tail, 0);
}

void queue_destroy(struct single_queue *q)
{
	free(q->data);
	q->data = NULL;
}

int queue_push(struct single_queue *q, void *queue_item)
{
	unsigned int tail = atomic_load_explicit(&q->tail, memory_order_relaxed);
	unsigned int next_tail;

	if (q->is_power_of_two) {
		next_tail = (tail + 1) & q->mask;
	} else {
		next_tail = (tail + 1) % q->size;
	}

	if (next_tail == atomic_load_explicit(&q->head, memory_order_acquire)) {
		return -1;
	}

	q->data[tail] = queue_item;
	atomic_store_explicit(&q->tail, next_tail, memory_order_release);
	return 0;
}

void *queue_pop(struct single_queue *q)
{
	unsigned int head = atomic_load_explicit(&q->head, memory_order_relaxed);

	if (head == atomic_load_explicit(&q->tail, memory_order_acquire)) {
		return NULL;
	}

	void *item = q->data[head];
	unsigned int next_head;

	if (q->is_power_of_two) {
		next_head = (head + 1) & q->mask;
	} else {
		next_head = (head + 1) % q->size;
	}

	atomic_store_explicit(&q->head, next_head, memory_order_release);
	return item;
}

void *queue_peek(struct single_queue *q)
{
	unsigned int head = atomic_load_explicit(&q->head, memory_order_acquire);
	if (head == atomic_load_explicit(&q->tail, memory_order_acquire)) {
		return NULL;
	}
	return q->data[head];
}

unsigned int queue_count(struct single_queue *q)
{
	unsigned int head = atomic_load_explicit(&q->head, memory_order_acquire);
	unsigned int tail = atomic_load_explicit(&q->tail, memory_order_acquire);

	if (tail >= head) {
		return tail - head;
	} else {
		return q->size - head + tail;
	}
}
