// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef __CLI_SINGLE_QUEUE_H__
#define __CLI_SINGLE_QUEUE_H__

#include <stdatomic.h>

/**
 * @file cli_single_queue.h
 * @brief Lock-free single-producer/single-consumer ring queue.
 */

/**
 * struct single_queue - SPSC ring-buffer queue.
 * @data: slot array backing storage.
 * @head: dequeue position.
 * @tail: enqueue position.
 * @size: number of allocated ring slots.
 * @mask: bitmask for wraparound when @size is power-of-two.
 * @is_power_of_two: true when ring math can use @mask directly.
 */
struct single_queue {
	void **data;
	atomic_uint head;
	atomic_uint tail;
	unsigned int size;
	unsigned int mask;
	int is_power_of_two;
};

/**
 * queue_init - initialize a single-queue with @size entries.
 * @q: queue instance.
 * @size: number of items supported by the ring.
 */
void queue_init(struct single_queue *q, unsigned int size);

/**
 * queue_destroy - free queue storage.
 * @q: queue instance.
 */
void queue_destroy(struct single_queue *q);

/**
 * queue_push - enqueue an item.
 * @q: queue instance.
 * @queue_item: item to add.
 *
 * Return: 0 on success, -1 when queue is full.
 */
int queue_push(struct single_queue *q, void *queue_item);

/**
 * queue_pop - dequeue one item.
 * @q: queue instance.
 *
 * Return: item pointer on success or %NULL if empty.
 */
void *queue_pop(struct single_queue *q);

/**
 * queue_count - read current occupancy.
 * @q: queue instance.
 *
 * Return: number of items currently queued.
 */
unsigned int queue_count(struct single_queue *q);

/**
 * queue_peek - read front item without removing it.
 * @q: queue instance.
 *
 * Return: next item pointer or %NULL when empty.
 */
void *queue_peek(struct single_queue *q);

#endif
