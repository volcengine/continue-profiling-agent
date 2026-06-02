// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CPA_DROP_POLICY_H
#define CPA_DROP_POLICY_H

#include "cpa_runtime.h"

/**
 * @file cpa_drop_policy.h
 * @brief Queue-pressure based dropping policy for sampled stack events.
 */

/**
 * enum drop_sample_result - current drop decision for one sample
 */
enum drop_sample_result {
	DROP_SAMPLE_RESULT_PASS = 0,
	DROP_SAMPLE_RESULT_HIGH_DROP = 1,
	DROP_SAMPLE_RESULT_FULL_DROP = 2,
};

/**
 * init_drop_policy - initialize drop policy state
 * @queue_size: queue capacity threshold used by the policy
 *
 * Set the initial queue watermark thresholds for pressure-based dropping.
 */
void init_drop_policy(unsigned int queue_size);

/**
 * update_drop_policy_queue_len - refresh drop level from current queue depth
 * @now_queue_len: latest observed queue length
 */
void update_drop_policy_queue_len(unsigned int now_queue_len);

/**
 * should_drop_sample - query the current queue-pressure verdict
 *
 * Return: drop decision for the sample currently being handled.
 */
enum drop_sample_result should_drop_sample(void);

/**
 * reset_drop_policy - reset policy state after pause or restart
 */
void reset_drop_policy(void);

#endif /* CPA_DROP_POLICY_H */
