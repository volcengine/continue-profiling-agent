// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cli.h"

#include "gunwinder/unwinder.h"

#include "cli_counter_heap_helper.h"
#include "cpa_nobpf_unwinder_event.h"
#include "cpa_unwinder.h"

#define TASK_COMM_LEN 16
#define PID_DECAY_BATCH 32
#define PID_DECAY_THRESHOLD 4
#define PID_DECAY_SHIFT_MAX 8
#define KALLSYMS_HASH_SEED 1469598103934665603ULL
#define KALLSYMS_HASH_PRIME 1099511628211ULL

struct pid_comm_payload {
	char comm[TASK_COMM_LEN];
	uint64_t last_epoch;
};

struct nobpf_unwinder_state {
	struct cli_counter_heap *store;
	pthread_mutex_t lock;
	int mutex_ready;
	uint64_t epoch;
	size_t decay_cursor;
	uint64_t retired_pid_count;
};

static struct nobpf_unwinder_state nobpf_state;

struct ksyms_monitor_state {
	pthread_t thread;
	int thread_running;
	int stop;
	int mutex_ready;
	pthread_mutex_t lock;
	int have_digest;
	uint64_t digest;
};

static struct ksyms_monitor_state ksyms_state;

static void payload_free(void *payload)
{
	free(payload);
}

static void reset_store_state(struct nobpf_unwinder_state *state)
{
	if (state->store) {
		cli_counter_heap_destroy(state->store, payload_free);
		state->store = NULL;
	}
	state->epoch = 0;
	state->decay_cursor = 0;
	state->retired_pid_count = 0;
}

int get_pid_comm_direct(int pid, char *comm)
{
	char path[128];
	int fd = -1, ret;

	if (kill(pid, 0)) {
		if (errno == ESRCH) {
			snprintf(comm, TASK_COMM_LEN, "<exit task>");
			return -1;
		}
		goto failed;
	}

	snprintf(path, sizeof(path), "/proc/%d/comm", pid);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		goto failed;
	}
	ret = read(fd, comm, TASK_COMM_LEN - 1);
	if (ret < 0) {
		goto failed;
	}
	comm[ret] = 0;
	if (ret > 0 && comm[ret - 1] == '\n')
		comm[ret - 1] = 0;
	close(fd);
	return 0;
failed:
	snprintf(comm, TASK_COMM_LEN, "<err read comm>");
	if (fd >= 0)
		close(fd);
	return -1;
}

static void copy_comm(char *dst, const char *src)
{
	memcpy(dst, src, TASK_COMM_LEN);
	dst[TASK_COMM_LEN - 1] = '\0';
}

static void decay_entry(struct cli_counter_heap_entry *entry, void *ctx)
{
	struct nobpf_unwinder_state *state = ctx;
	if (!state || !entry || !entry->payload)
		return;
	struct pid_comm_payload *payload = entry->payload;
	uint64_t gap = state->epoch - payload->last_epoch;
	if (gap < PID_DECAY_THRESHOLD)
		return;
	if (entry->value <= 1)
		return;
	uint64_t shift = gap / PID_DECAY_THRESHOLD;
	if (shift > PID_DECAY_SHIFT_MAX)
		shift = PID_DECAY_SHIFT_MAX;
	uint64_t new_value = entry->value >> shift;
	if (!new_value)
		new_value = 1;
	cli_counter_heap_update_value(state->store, entry, new_value);
}

static void apply_decay(struct nobpf_unwinder_state *state)
{
	if (!state || !state->store)
		return;
	cli_counter_heap_for_each_chunk(state->store, &state->decay_cursor, PID_DECAY_BATCH, decay_entry, state);
}

int get_pid_comm_auto_retire(int pid, char *comm)
{
	if (pid <= 0 || !comm)
		return -1;

	struct nobpf_unwinder_state *state = &nobpf_state;
	if (!state->mutex_ready || !state->store)
		return get_pid_comm_direct(pid, comm);

	pthread_mutex_lock(&state->lock);

	struct cli_counter_heap_entry *entry = cli_counter_heap_find(state->store, pid);
	if (entry) {
		struct pid_comm_payload *payload = entry->payload;
		copy_comm(comm, payload->comm);
		payload->last_epoch = state->epoch;
		cli_counter_heap_increment(state->store, entry, 1);
		pthread_mutex_unlock(&state->lock);
		return 0;
	}

	pthread_mutex_unlock(&state->lock);

	if (get_pid_comm_direct(pid, comm))
		return -1;

	struct pid_comm_payload *payload = calloc(1, sizeof(struct pid_comm_payload));
	if (!payload)
		return -1;

	copy_comm(payload->comm, comm);

	pthread_mutex_lock(&state->lock);
	entry = cli_counter_heap_find(state->store, pid);
	if (entry) {
		free(payload);
		struct pid_comm_payload *stored = entry->payload;
		copy_comm(comm, stored->comm);
		stored->last_epoch = state->epoch;
		cli_counter_heap_increment(state->store, entry, 1);
		pthread_mutex_unlock(&state->lock);
		return 0;
	}
	entry = cli_counter_heap_insert(state->store, pid, payload, 1);
	if (!entry) {
		pthread_mutex_unlock(&state->lock);
		free(payload);
		return -1;
	}
	payload->last_epoch = state->epoch;
	pthread_mutex_unlock(&state->lock);

	return 0;
}

static void reinsert_entries(struct nobpf_unwinder_state *state, struct cli_counter_heap_entry **entries, size_t count, uint64_t retired_delta)
{
	if (!count && !retired_delta)
		return;

	pthread_mutex_lock(&state->lock);

	if (retired_delta)
		state->retired_pid_count += retired_delta;

	for (size_t i = 0; i < count; i++) {
		struct cli_counter_heap_entry *entry = entries[i];
		struct pid_comm_payload *payload = entry->payload;

		if (payload)
			payload->last_epoch = state->epoch;

		struct cli_counter_heap_entry *existing = cli_counter_heap_find(state->store, entry->key);

		if (existing) {
			struct pid_comm_payload *existing_payload = existing->payload;
			if (existing_payload)
				existing_payload->last_epoch = state->epoch;
			cli_counter_heap_increment(state->store, existing, entry->value);
			cli_counter_heap_entry_destroy(entry, payload_free);
			continue;
		}
		if (cli_counter_heap_push_entry(state->store, entry))
			cli_counter_heap_entry_destroy(entry, payload_free);
	}

	pthread_mutex_unlock(&state->lock);
}

static void nobpf_unwinder_timer(void *worker_ctx)
{
	struct nobpf_unwinder_state *state = worker_ctx;
	struct cli_counter_heap_entry *popped[10] = { 0 };
	size_t popped_count = 0;

	if (!state || !state->store || !state->mutex_ready)
		return;

	pthread_mutex_lock(&state->lock);

	state->epoch++;
	apply_decay(state);

	while (popped_count < 10) {
		struct cli_counter_heap_entry *entry = cli_counter_heap_pop_min(state->store);
		if (!entry)
			break;
		popped[popped_count++] = entry;
	}

	if (!cli_counter_heap_size(state->store))
		state->decay_cursor = 0;

	pthread_mutex_unlock(&state->lock);

	if (!popped_count)
		return;

	struct cli_counter_heap_entry *alive[10] = { 0 };
	size_t alive_count = 0;
	uint64_t retired_count = 0;

	for (size_t i = 0; i < popped_count; i++) {
		struct cli_counter_heap_entry *entry = popped[i];
		int ret = kill(entry->key, 0);
		int err = errno;
		if (!ret || (ret < 0 && err == EPERM)) {
			alive[alive_count++] = entry;
			continue;
		}

		struct exit_event *e = malloc(sizeof(struct exit_event));
		if (!e)
			return;

		e->exit_ts = get_current_uptime_ns();
		e->pid = entry->key;

		cpa_add_pid_exit_event(e);

		cli_counter_heap_entry_destroy(entry, payload_free);
		retired_count++;
	}

	reinsert_entries(state, alive, alive_count, retired_count);
}

static enum cpa_worker_init_result nobpf_unwinder_init(void *cli_ctx, void *worker_ctx)
{
	const char *backend = get_arg_by_name(cli_ctx, "backend");
	if (strncmp(backend, "bpf", strlen("bpf")) == 0)
		return CPA_INIT_SKIP;

	struct nobpf_unwinder_state *state = worker_ctx;
	if (!state)
		return CPA_INIT_FAILED;
	if (!state->mutex_ready) {
		if (pthread_mutex_init(&state->lock, NULL))
			return CPA_INIT_FAILED;
		state->mutex_ready = 1;
	}
	if (state->store)
		return 0;
	state->store = cli_counter_heap_create(256);
	if (!state->store)
		return CPA_INIT_FAILED;
	state->epoch = 0;
	state->decay_cursor = 0;
	state->retired_pid_count = 0;
	return 0;
}

static void nobpf_unwinder_destroy(void *worker_ctx)
{
	struct nobpf_unwinder_state *state = worker_ctx;
	if (!state)
		return;
	if (state->mutex_ready)
		pthread_mutex_lock(&state->lock);
	reset_store_state(state);
	if (!state->mutex_ready)
		return;
	pthread_mutex_unlock(&state->lock);
	pthread_mutex_destroy(&state->lock);
	state->mutex_ready = 0;
}

static void nobpf_unwinder_pause(void *worker_ctx)
{
	struct nobpf_unwinder_state *state = worker_ctx;
	if (!state || !state->mutex_ready)
		return;
	pthread_mutex_lock(&state->lock);
	reset_store_state(state);
	pthread_mutex_unlock(&state->lock);
}

static void nobpf_unwinder_restore(void *worker_ctx)
{
	struct nobpf_unwinder_state *state = worker_ctx;
	if (!state || !state->mutex_ready)
		return;
	pthread_mutex_lock(&state->lock);
	if (!state->store)
		state->store = cli_counter_heap_create(256);
	state->epoch = 0;
	state->decay_cursor = 0;
	state->retired_pid_count = 0;
	pthread_mutex_unlock(&state->lock);
}

static uint64_t fnv1a64_update(uint64_t hash, const char *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		hash ^= (unsigned char)buf[i];
		hash *= KALLSYMS_HASH_PRIME;
	}

	return hash;
}

static int read_kallsyms_hash(uint64_t *out)
{
	int fd = open("/proc/kallsyms", O_RDONLY);
	uint64_t hash = KALLSYMS_HASH_SEED;

	if (fd < 0)
		return CPA_INIT_FAILED;

	char buffer[4096];

	while (1) {
		ssize_t n = read(fd, buffer, sizeof(buffer));

		if (n < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			return CPA_INIT_FAILED;
		}
		if (!n)
			break;
		hash = fnv1a64_update(hash, buffer, n);
	}
	close(fd);

	*out = hash;
	return CPA_INIT_SUCCESS;
}

static void cli_output_hash(uint64_t hash)
{
	CLI_OUTPUT("kallsyms hash: %016llx", (unsigned long long)hash);
}

static int ksyms_should_stop(struct ksyms_monitor_state *state)
{
	if (!state || !state->mutex_ready)
		return 1;
	int flag;
	pthread_mutex_lock(&state->lock);
	flag = state->stop;
	pthread_mutex_unlock(&state->lock);
	return flag;
}

static void *check_ksyms_thread(void *arg)
{
	struct ksyms_monitor_state *state = arg;
	while (!ksyms_should_stop(state)) {
		for (int i = 0; i < 60; i++) {
			if (ksyms_should_stop(state))
				break;
			sleep(1);
		}

		uint64_t digest;
		if (!read_kallsyms_hash(&digest)) {
			int changed = 0;
			uint64_t old_digest = 0;
			int had_old = 0;

			pthread_mutex_lock(&state->lock);
			if (!state->have_digest || state->digest != digest) {
				if (state->have_digest) {
					had_old = 1;
					old_digest = state->digest;
				}
				state->digest = digest;
				state->have_digest = 1;
				changed = 1;
			}
			pthread_mutex_unlock(&state->lock);
			if (changed) {
				CLI_OUTPUT("kallsyms digest changed, need reload.");
				if (had_old) {
					CLI_OUTPUT("old digest:");
					cli_output_hash(old_digest);
				}
				CLI_OUTPUT("new digest:");
				cli_output_hash(digest);
				cpa_add_ksyms_reload_event();
			}
		}
	}
	pthread_mutex_lock(&state->lock);
	state->thread_running = 0;
	pthread_mutex_unlock(&state->lock);
	return NULL;
}

static int ksyms_start_thread(struct ksyms_monitor_state *state)
{
	if (!state || !state->mutex_ready)
		return -1;
	pthread_mutex_lock(&state->lock);
	if (state->thread_running) {
		pthread_mutex_unlock(&state->lock);
		return 0;
	}
	state->stop = 0;
	state->have_digest = 0;
	if (read_kallsyms_hash(&state->digest)) {
		pthread_mutex_unlock(&state->lock);
		return -1;
	}
	state->have_digest = 1;
	pthread_mutex_unlock(&state->lock);
	if (pthread_create(&state->thread, NULL, check_ksyms_thread, state))
		return -1;
	pthread_mutex_lock(&state->lock);
	state->thread_running = 1;
	pthread_mutex_unlock(&state->lock);
	return 0;
}

static void ksyms_stop_thread(struct ksyms_monitor_state *state)
{
	if (!state || !state->mutex_ready)
		return;
	pthread_mutex_lock(&state->lock);
	if (!state->thread_running) {
		state->have_digest = 0;
		state->stop = 0;
		pthread_mutex_unlock(&state->lock);
		return;
	}
	state->stop = 1;
	pthread_mutex_unlock(&state->lock);
	pthread_join(state->thread, NULL);
	pthread_mutex_lock(&state->lock);
	state->have_digest = 0;
	state->stop = 0;
	pthread_mutex_unlock(&state->lock);
}

static enum cpa_worker_init_result ksyms_check_init(void *cli_ctx, void *worker_ctx)
{
	struct ksyms_monitor_state *state = worker_ctx;
	if (!state)
		return CPA_INIT_FAILED;
	if (!state->mutex_ready) {
		if (pthread_mutex_init(&state->lock, NULL))
			return -1;
		state->mutex_ready = 1;
	}

	if (ksyms_start_thread(state) < 0)
		return CPA_INIT_FAILED;

	return CPA_INIT_SUCCESS;
}

static void ksyms_check_destroy(void *worker_ctx)
{
	struct ksyms_monitor_state *state = worker_ctx;
	if (!state || !state->mutex_ready)
		return;
	ksyms_stop_thread(state);
	pthread_mutex_destroy(&state->lock);
	state->mutex_ready = 0;
}

static void ksyms_check_pause(void *worker_ctx)
{
	struct ksyms_monitor_state *state = worker_ctx;
	ksyms_stop_thread(state);
}

static void ksyms_check_restore(void *worker_ctx)
{
	struct ksyms_monitor_state *state = worker_ctx;
	if (!state || !state->mutex_ready)
		return;
	ksyms_start_thread(state);
}

struct cpa_worker pid_tracker_worker = {
	.worker_name = "nobpf_unwinder_event",
	.worker_ctx = &nobpf_state,
	.worker_index = 10,
	.init_fn = nobpf_unwinder_init,
	.destroy_fn = nobpf_unwinder_destroy,
	.pause_fn = nobpf_unwinder_pause,
	.restore_fn = nobpf_unwinder_restore,
	.timer_fn = nobpf_unwinder_timer,
	.main_worker_fn = NULL,
};

struct cpa_worker ksyms_check_worker = {
	.worker_name = "ksyms_check_worker",
	.worker_ctx = &ksyms_state,
	.worker_index = 10,
	.init_fn = ksyms_check_init,
	.destroy_fn = ksyms_check_destroy,
	.pause_fn = ksyms_check_pause,
	.restore_fn = ksyms_check_restore,
	.timer_fn = NULL,
	.main_worker_fn = NULL,
};

void get_pid_tracker_stat(struct pid_tracker_stat *stat)
{
	if (!stat)
		return;
	struct nobpf_unwinder_state *state = &nobpf_state;
	memset(stat, 0, sizeof(*stat));
	if (!state->mutex_ready)
		return;
	pthread_mutex_lock(&state->lock);
	stat->retired_pid_count = state->retired_pid_count;
	stat->tracked_pid_count = state->store ? (uint64_t)cli_counter_heap_size(state->store) : 0;
	pthread_mutex_unlock(&state->lock);
}
