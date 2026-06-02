// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "cpa_drop_policy.h"
#include <stdbool.h>
#include <pthread.h>

struct drop_policy {
	unsigned int queue_size;
	unsigned int drop_rate_threshold;
	bool full_drop;
};

struct drop_policy drop_policy = { 0 };

#define RAND_MAX_LIMIT 32767
unsigned int drop_rand_seed = 123456789;
static pthread_mutex_t drop_policy_lock = PTHREAD_MUTEX_INITIALIZER;

void init_drop_policy(unsigned int queue_size)
{
	pthread_mutex_lock(&drop_policy_lock);
	drop_policy.queue_size = queue_size;
	drop_policy.drop_rate_threshold = 0;
	drop_policy.full_drop = false;
	pthread_mutex_unlock(&drop_policy_lock);
}

void update_drop_policy_queue_len(unsigned int now_queue_len)
{
	pthread_mutex_lock(&drop_policy_lock);
	if (drop_policy.queue_size == 0) {
		drop_policy.drop_rate_threshold = RAND_MAX_LIMIT;
		drop_policy.full_drop = true;
		pthread_mutex_unlock(&drop_policy_lock);
		return;
	}
	drop_policy.full_drop = false;
	// Three segments for drop rate calculation
	if (now_queue_len < drop_policy.queue_size / 8) {
		drop_policy.drop_rate_threshold = 0;
	} else if (now_queue_len < drop_policy.queue_size - drop_policy.queue_size / 32) {
		// Linear increase between lower and upper thresholds
		unsigned int lower_threshold = drop_policy.queue_size / 8;
		unsigned int upper_threshold = drop_policy.queue_size - drop_policy.queue_size / 32;
		drop_policy.drop_rate_threshold = (now_queue_len - lower_threshold) * RAND_MAX_LIMIT / (upper_threshold - lower_threshold);
	} else {
		drop_policy.drop_rate_threshold = RAND_MAX_LIMIT;
		drop_policy.full_drop = true;
	}
	pthread_mutex_unlock(&drop_policy_lock);
}

static unsigned int fast_rand(void)
{
	drop_rand_seed = drop_rand_seed * 1103515245 + 12345;
	return (drop_rand_seed >> 16) & 0x7FFF;
}

void reset_drop_policy(void)
{
	pthread_mutex_lock(&drop_policy_lock);
	drop_policy.full_drop = false;
	drop_policy.drop_rate_threshold = 0;
	pthread_mutex_unlock(&drop_policy_lock);
}

enum drop_sample_result should_drop_sample(void)
{
	enum drop_sample_result result;

	pthread_mutex_lock(&drop_policy_lock);
	if (drop_policy.full_drop) {
		result = DROP_SAMPLE_RESULT_FULL_DROP;
	} else {
		unsigned int rand_val = fast_rand();
		result = rand_val < drop_policy.drop_rate_threshold ? DROP_SAMPLE_RESULT_HIGH_DROP : DROP_SAMPLE_RESULT_PASS;
	}
	pthread_mutex_unlock(&drop_policy_lock);

	return result;
}
