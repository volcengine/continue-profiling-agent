// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "cpa_unwind_queue.h"
#include "cli_common.h"
#include "cli_output.h"
#include "cpa_drop_policy.h"
#include "cpa_sample_pool.h"
#include "uthash.h"

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <time.h>

#define CPA_PID_EXIT_QUEUE_SLOTS 32768
/*
 * Samples captured before an exit can still be in the kernel buffers: the
 * per-process unwinder state is freed only this long after the exit.
 */
#define CPA_PID_EXIT_GRACE_NS (10ULL * 1000ULL * 1000ULL * 1000ULL)
/* Exits are reaped in batches at most this often while they keep coming. */
#define CPA_PID_EXIT_REAP_TICK_NS (1000ULL * 1000ULL * 1000ULL)

/* Hashed as raw bytes: no implicit padding, every byte is a named member. */
struct pending_key {
	uint32_t tgid;
	uint32_t pad;
	uint64_t unique_id;
};
_Static_assert(sizeof(struct pending_key) == 16, "pending_key must not have implicit padding");

struct pending_instance {
	struct pending_key key;
	unsigned int count;
	/* exit of this instance, released once its last sample is finished */
	struct exit_event *parked_exit;
	UT_hash_handle hh;
};

/* Exits ready to be reaped, linked through a node of their own. */
struct ready_exit {
	struct exit_event *exit;
	struct ready_exit *next;
};

/*
 * One lane per unwind worker.  Every field is the lane's own: the lock
 * guards the sample ring, the exit ring, the pending index and the ready
 * exits.  Each ring is pushed and popped only through its paired helpers
 * (lane_admit_sample_locked() / lane_retire_sample_locked(),
 * lane_exit_push_locked() / lane_exit_pop_locked()), always under the lock.
 *
 * Waking the worker: it sleeps on a semaphore rather than a condition
 * variable because set_stop() runs in a signal handler, where only
 * sem_post() and lock-free atomics are allowed.  The worker announces itself
 * in @waiting and re-checks for work before sleeping; a waker posts only
 * when it takes that announcement, so a wake-up is never lost and at most
 * one is pending.
 */
struct unwind_lane {
	pthread_mutex_t lock;
	struct single_queue samples;
	struct single_queue exits;
	struct pending_instance *pending;
	/*
	 * Queued + being unwound.  Counted per accepted sample, not through the
	 * per-instance index, which may lack an entry after a failed allocation.
	 */
	unsigned int pending_total;
	struct ready_exit *ready_exits;
	sem_t wake;
	atomic_bool waiting;
	atomic_bool kicked;
};

static struct unwind_lane lanes[CPA_UNWIND_LANES_MAX];
/* Fixed for the session once the queue is initialized. */
static unsigned int lane_count = 1;
static bool lane_locks_initialized;
/*
 * One admission budget for all lanes: a sample takes a credit before it is
 * queued and gives it back once it is unwound.  Queued and worker-held
 * samples together never exceed queue_size - 1 + lanes: the ring of one
 * lane, as with one worker, plus one sample held by each worker.  A lane's
 * ring holds queue_size - 1 too, so one busy process is refused no earlier
 * than with one lane, and many lanes no later.
 */
static atomic_uint admitted;
static unsigned int admit_limit;
/*
 * Exits queued in all lanes.  The lanes share the capacity of one exit
 * queue (CPA_PID_EXIT_QUEUE_SLOTS - 1): each lane's ring could hold all of
 * it, so a burst whose pids hash to one lane is held as with one lane.
 */
static atomic_uint exits_queued;
static bool queues_initialized;
static bool sample_pool_initialized;
/*
 * The wake semaphores of all lanes are initialized once and never destroyed
 * (static storage): a set_stop() racing a cleanup always posts a live one.
 */
static atomic_bool lane_wake_initialized;
static atomic_bool accept_events;

static void lane_wake(struct unwind_lane *lane)
{
	if (atomic_exchange(&lane->waiting, false))
		sem_post(&lane->wake);
}

void cpa_unwind_queue_kick(void)
{
	if (!atomic_load_explicit(&lane_wake_initialized, memory_order_acquire))
		return;
	for (unsigned int i = 0; i < lane_count; i++) {
		atomic_store(&lanes[i].kicked, true);
		lane_wake(&lanes[i]);
	}
}

unsigned int cpa_unwind_queue_lanes(void)
{
	return lane_count;
}

/*
 * A multiplicative hash spreads neighbouring pids (a burst of forks) over
 * the lanes; one lane needs no hash.  Of a process, never a thread.
 */
unsigned int cpa_unwind_lane_of(uint32_t tgid)
{
	if (lane_count == 1)
		return 0;
	return (unsigned int)((((uint64_t)tgid * 0x9E3779B97F4A7C15ULL) >> 32) % lane_count);
}

unsigned int cpa_unwind_workers_max(void)
{
	int cpus = get_nprocs();

	if (cpus < 1)
		cpus = 1;
	return (unsigned int)cpus < CPA_UNWIND_LANES_MAX ? (unsigned int)cpus : CPA_UNWIND_LANES_MAX;
}

int cpa_unwind_workers_parse(const char *value, unsigned int max, unsigned int *workers_out)
{
	unsigned long n = 0;

	if (!value || !*value)
		return -EINVAL;
	for (const char *p = value; *p; p++) {
		if (!isdigit((unsigned char)*p))
			return -EINVAL;
		n = n * 10 + (unsigned long)(*p - '0');
		if (n > max)
			return -ERANGE;
	}
	if (n < 1)
		return -ERANGE;
	*workers_out = (unsigned int)n;
	return 0;
}

static struct unwind_lane *lane_of_tgid(uint32_t tgid)
{
	return &lanes[cpa_unwind_lane_of(tgid)];
}

static uint64_t monotonic_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static struct pending_key sample_key(const struct stack_sample *sample)
{
	return (struct pending_key){
		.tgid = (uint32_t)sample->tgid,
		.unique_id = sample->info ? sample->info->unique_id : 0,
	};
}

/*
 * The exit's node is allocated when it becomes ready; without memory the
 * exit is freed unreaped, as if it had been lost: its state waits for the
 * lazy paths.
 */
static void ready_exit_push_locked(struct unwind_lane *lane, struct exit_event *exit_event)
{
	struct ready_exit *node = malloc(sizeof(*node));

	if (!node) {
		free(exit_event);
		return;
	}
	node->exit = exit_event;
	node->next = lane->ready_exits;
	lane->ready_exits = node;
}

static void pending_add_locked(struct unwind_lane *lane, const struct stack_sample *sample)
{
	struct pending_key key = sample_key(sample);
	struct pending_instance *entry = NULL;

	lane->pending_total++;
	HASH_FIND(hh, lane->pending, &key, sizeof(key), entry);
	if (entry) {
		entry->count++;
		return;
	}
	entry = calloc(1, sizeof(*entry));
	if (!entry) {
		CLI_ERROR("cpa unwind queue: cannot allocate a pending entry");
		return;
	}
	entry->key = key;
	entry->count = 1;
	HASH_ADD(hh, lane->pending, key, sizeof(entry->key), entry);
}

/*
 * The one way into a lane: the sample takes an admission credit, enters the
 * ring and is counted pending; the worker is woken.  -1, credit given back,
 * if refused.  Its way out is lane_retire_sample_locked().
 */
static int lane_admit_sample_locked(struct unwind_lane *lane, struct stack_sample *sample)
{
	if (atomic_fetch_add(&admitted, 1) >= admit_limit) {
		atomic_fetch_sub(&admitted, 1);
		return -1;
	}
	if (queue_push(&lane->samples, sample)) {
		atomic_fetch_sub(&admitted, 1);
		return -1;
	}
	pending_add_locked(lane, sample);
	lane_wake(lane);
	return 0;
}

/*
 * A sample admitted to @lane is done: its credit and pending count go back.
 * Never after the lane was drained: drains run only while no worker holds a
 * sample (an accepted pause parks them between samples, stop joins them
 * first), so a finish without its pending count is a broken caller, told
 * once rather than taken from another sample's count.
 */
static void lane_retire_sample_locked(struct unwind_lane *lane, const struct stack_sample *sample)
{
	struct pending_key key = sample_key(sample);
	struct pending_instance *entry = NULL;
	static atomic_bool told;

	if (lane->pending_total) {
		lane->pending_total--;
		atomic_fetch_sub(&admitted, 1);
	} else if (!atomic_exchange(&told, true)) {
		CLI_ERROR("cpa unwind queue: a sample of tgid %d finished after its lane was drained", sample->tgid);
	}
	HASH_FIND(hh, lane->pending, &key, sizeof(key), entry);
	if (!entry || --entry->count > 0)
		return;
	if (entry->parked_exit)
		ready_exit_push_locked(lane, entry->parked_exit);
	HASH_DEL(lane->pending, entry);
	free(entry);
}

static void pending_clear_locked(struct unwind_lane *lane)
{
	struct pending_instance *entry = NULL;
	struct pending_instance *tmp = NULL;

	HASH_ITER(hh, lane->pending, entry, tmp) {
		free(entry->parked_exit);
		HASH_DEL(lane->pending, entry);
		free(entry);
	}
	atomic_fetch_sub(&admitted, lane->pending_total);
	lane->pending_total = 0;
}

/*
 * The exit ring of a lane and the shared exits_queued credit move together:
 * push takes a credit (0, or -1 with nothing taken when the shared capacity
 * or the ring is full), pop gives it back.  Lane lock held.
 */
static int lane_exit_push_locked(struct unwind_lane *lane, struct exit_event *exit_event)
{
	if (atomic_fetch_add(&exits_queued, 1) >= CPA_PID_EXIT_QUEUE_SLOTS - 1 ||
	    queue_push(&lane->exits, exit_event)) {
		atomic_fetch_sub(&exits_queued, 1);
		return -1;
	}
	return 0;
}

static struct exit_event *lane_exit_pop_locked(struct unwind_lane *lane)
{
	struct exit_event *exit_event = queue_pop(&lane->exits);

	if (exit_event)
		atomic_fetch_sub(&exits_queued, 1);
	return exit_event;
}

/*
 * An exit whose instance still has samples in flight waits on their pending
 * entry; the last sample to finish releases it.  A second exit of the same
 * instance is dropped: the parked one reaps it.  False when nothing is
 * pending, i.e. the exit is ready now.
 */
static bool exit_park_locked(struct unwind_lane *lane, struct exit_event *exit_event)
{
	struct pending_key key = {
		.tgid = exit_event->gu.pid,
		.unique_id = exit_event->gu.start_time,
	};
	struct pending_instance *entry = NULL;

	HASH_FIND(hh, lane->pending, &key, sizeof(key), entry);
	if (!entry)
		return false;
	if (entry->parked_exit)
		free(exit_event);
	else
		entry->parked_exit = exit_event;
	return true;
}

static void lanes_destroy_rings(void)
{
	for (unsigned int i = 0; i < lane_count; i++) {
		queue_destroy(&lanes[i].samples);
		queue_destroy(&lanes[i].exits);
	}
}

int cpa_unwind_queue_init(int queue_size, unsigned int requested_lanes)
{
	unsigned int sample_pool_limit;
	bool rings_ok = true;

	if (requested_lanes < 1 || requested_lanes > CPA_UNWIND_LANES_MAX) {
		CLI_ERROR("cpa unwind queue: %u lanes out of 1..%d", requested_lanes, CPA_UNWIND_LANES_MAX);
		return -1;
	}
	atomic_store(&accept_events, false);
	atomic_store(&exits_queued, 0);
	lane_count = requested_lanes;
	admit_limit = (unsigned int)queue_size - 1 + lane_count;
	atomic_store(&admitted, 0);
	if (!lane_locks_initialized) {
		for (unsigned int i = 0; i < CPA_UNWIND_LANES_MAX; i++)
			pthread_mutex_init(&lanes[i].lock, NULL);
		lane_locks_initialized = true;
	}
	if (!atomic_load_explicit(&lane_wake_initialized, memory_order_acquire)) {
		for (unsigned int i = 0; i < CPA_UNWIND_LANES_MAX; i++) {
			if (sem_init(&lanes[i].wake, 0, 0) == 0)
				continue;
			CLI_ERROR("cpa unwind queue: sem_init failed: %s", strerror(errno));
			while (i--)
				sem_destroy(&lanes[i].wake);
			return -1;
		}
		atomic_store_explicit(&lane_wake_initialized, true, memory_order_release);
	}
	for (unsigned int i = 0; i < lane_count; i++) {
		atomic_store(&lanes[i].waiting, false);
		atomic_store(&lanes[i].kicked, false);
	}
	if (set_stop_notify(cpa_unwind_queue_kick)) {
		CLI_ERROR("cpa unwind queue: another set_stop() hook is published, there is one");
		return -1;
	}

	/*
	 * Every lane's ring can hold every sample the budget allows: a process'
	 * samples all go to one lane, and a single busy process must not be
	 * refused earlier than with one lane.
	 */
	for (unsigned int i = 0; i < lane_count; i++) {
		queue_init(&lanes[i].samples, queue_size);
		queue_init(&lanes[i].exits, CPA_PID_EXIT_QUEUE_SLOTS);
		rings_ok = rings_ok && lanes[i].samples.data && lanes[i].exits.data;
	}
	if (!rings_ok) {
		CLI_ERROR("cpa unwind queue: cannot allocate the rings");
		lanes_destroy_rings();
		clear_stop_notify(cpa_unwind_queue_kick);
		return -1;
	}
	queues_initialized = true;

	/* keep at most one free buffer per queue slot */
	sample_pool_limit = cpa_sample_pool_default_limit();
	if (sample_pool_limit > (unsigned int)queue_size)
		sample_pool_limit = (unsigned int)queue_size;
	cpa_sample_pool_init(sample_pool_limit);
	sample_pool_initialized = true;

	init_drop_policy(queue_size);
	return 0;
}

void cpa_unwind_queue_set_accepting(bool accepting)
{
	atomic_store_explicit(&accept_events, accepting, memory_order_release);
}

bool cpa_unwind_queue_accepting(void)
{
	return atomic_load_explicit(&accept_events, memory_order_acquire);
}

/*
 * Drop what every lane holds; the workers must not be holding a sample.  The
 * unwinder runs it from one owner at a time (an accepted pause keeps
 * ownership until it has rebuilt), and every pop holds the lane lock anyway.
 */
static void lanes_drain(void)
{
	for (unsigned int i = 0; i < lane_count; i++) {
		struct unwind_lane *lane = &lanes[i];
		struct stack_sample *sample;
		struct exit_event *exit_event;

		pthread_mutex_lock(&lane->lock);
		while ((sample = queue_pop(&lane->samples)) != NULL) {
			lane_retire_sample_locked(lane, sample);
			cpa_sample_free(sample);
		}
		while ((exit_event = lane_exit_pop_locked(lane)) != NULL)
			free(exit_event);
		pending_clear_locked(lane);
		while (lane->ready_exits) {
			struct ready_exit *next = lane->ready_exits->next;

			free(lane->ready_exits->exit);
			free(lane->ready_exits);
			lane->ready_exits = next;
		}
		pthread_mutex_unlock(&lane->lock);
	}
	update_drop_policy_queue_len(0);
}

void cpa_unwind_queue_cleanup(bool destroy)
{
	if (queues_initialized)
		lanes_drain();
	if (!destroy)
		return;
	if (sample_pool_initialized) {
		/* a capture callback still running falls back to malloc()/free() */
		cpa_sample_pool_destroy();
		sample_pool_initialized = false;
	}
	if (queues_initialized) {
		/* returns once no set_stop() is still in the hook */
		clear_stop_notify(cpa_unwind_queue_kick);
		lanes_destroy_rings();
		queues_initialized = false;
	}
}

struct stack_sample *cpa_unwind_queue_pop_sample(unsigned int lane_index)
{
	struct unwind_lane *lane = &lanes[lane_index];
	struct stack_sample *sample;

	pthread_mutex_lock(&lane->lock);
	sample = queue_pop(&lane->samples);
	pthread_mutex_unlock(&lane->lock);
	return sample;
}

void cpa_unwind_queue_retire_sample(struct stack_sample *sample)
{
	struct unwind_lane *lane;

	if (!sample)
		return;
	lane = lane_of_tgid((uint32_t)sample->tgid);
	pthread_mutex_lock(&lane->lock);
	lane_retire_sample_locked(lane, sample);
	pthread_mutex_unlock(&lane->lock);
	cpa_sample_free(sample);
}

unsigned int cpa_unwind_queue_pending_samples(void)
{
	unsigned int total = 0;

	for (unsigned int i = 0; i < lane_count; i++) {
		pthread_mutex_lock(&lanes[i].lock);
		total += lanes[i].pending_total;
		pthread_mutex_unlock(&lanes[i].lock);
	}
	return total;
}

unsigned int cpa_unwind_queue_admitted(void)
{
	return atomic_load(&admitted);
}

/* Read lock-free: an estimate under load. */
unsigned int cpa_unwind_queue_sample_len(void)
{
	unsigned int total = 0;

	if (!queues_initialized)
		return 0;
	for (unsigned int i = 0; i < lane_count; i++)
		total += queue_count(&lanes[i].samples);
	return total;
}

unsigned int cpa_unwind_queue_exit_len(void)
{
	return atomic_load(&exits_queued);
}

/*
 * Exits arrive in time order, so only the head is examined; an exit still
 * waiting on samples is parked on their pending entry.
 */
unsigned int cpa_unwind_queue_pop_ready_exits(unsigned int lane_index, struct exit_event **out, unsigned int max_events,
					      uint64_t *next_deadline_ns)
{
	struct unwind_lane *lane = &lanes[lane_index];
	unsigned int collected = 0;
	uint64_t now = monotonic_ns();

	*next_deadline_ns = 0;
	if (!queues_initialized || !out || !max_events)
		return 0;

	pthread_mutex_lock(&lane->lock);
	while (lane->ready_exits && collected < max_events) {
		struct ready_exit *node = lane->ready_exits;

		out[collected++] = node->exit;
		lane->ready_exits = node->next;
		free(node);
	}
	while (collected < max_events) {
		struct exit_event *exit_event = queue_peek(&lane->exits);

		if (!exit_event)
			break;
		if (exit_event->exit_ts + CPA_PID_EXIT_GRACE_NS > now) {
			uint64_t due = exit_event->exit_ts + CPA_PID_EXIT_GRACE_NS;

			/* round up: one wake-up reaps a whole tick of exits */
			*next_deadline_ns = (due / CPA_PID_EXIT_REAP_TICK_NS + 1) * CPA_PID_EXIT_REAP_TICK_NS;
			break;
		}
		lane_exit_pop_locked(lane);
		if (!exit_park_locked(lane, exit_event))
			out[collected++] = exit_event;
	}
	pthread_mutex_unlock(&lane->lock);
	return collected;
}

/*
 * Checked after announcing the wait.  An exit the caller did not know about
 * (it computed no deadline) must be looked at before sleeping without one.
 */
static bool lane_has_work(struct unwind_lane *lane, uint64_t deadline_ns)
{
	return queue_count(&lane->samples) || lane->ready_exits || atomic_load(&lane->kicked) || should_stop() ||
	       (!deadline_ns && queue_count(&lane->exits));
}

struct stack_sample *cpa_unwind_queue_wait_sample(unsigned int lane_index, uint64_t deadline_ns)
{
	struct unwind_lane *lane = &lanes[lane_index];
	bool busy;
	int ret;

	atomic_store(&lane->waiting, true);
	pthread_mutex_lock(&lane->lock);
	busy = lane_has_work(lane, deadline_ns);
	pthread_mutex_unlock(&lane->lock);
	if (!busy) {
		if (deadline_ns) {
			uint64_t now = monotonic_ns();
			uint64_t left = deadline_ns > now ? deadline_ns - now : 0;
			struct timespec abs;

			/* sem_timedwait() only takes CLOCK_REALTIME */
			clock_gettime(CLOCK_REALTIME, &abs);
			abs.tv_sec += left / 1000000000ULL;
			abs.tv_nsec += left % 1000000000ULL;
			if (abs.tv_nsec >= 1000000000L) {
				abs.tv_sec++;
				abs.tv_nsec -= 1000000000L;
			}
			do {
				ret = sem_timedwait(&lane->wake, &abs);
			} while (ret && errno == EINTR && !should_stop());
		} else {
			do {
				ret = sem_wait(&lane->wake);
			} while (ret && errno == EINTR && !should_stop());
		}
	}
	atomic_store(&lane->waiting, false);
	atomic_store(&lane->kicked, false);
	return cpa_unwind_queue_pop_sample(lane_index);
}

int cpa_add_pid_exit_event(struct exit_event *exit)
{
	struct unwind_lane *lane;
	bool first;
	int ret;

	if (!exit || should_stop() || !cpa_unwind_queue_accepting() || !queues_initialized)
		return -1;

	lane = lane_of_tgid(exit->gu.pid);
	/*
	 * Behind other exits the worker already sleeps until the head's
	 * deadline; only the first one gives it a deadline to learn about.
	 * "First" is decided under the lane lock, the lock its worker pops
	 * exits and checks for work with: decided outside it, the worker could
	 * pop the last exit and sleep with no deadline between the check and
	 * the push, and this exit would wait for an unrelated wake-up.
	 */
	pthread_mutex_lock(&lane->lock);
	first = queue_count(&lane->exits) == 0;
	ret = lane_exit_push_locked(lane, exit);
	pthread_mutex_unlock(&lane->lock);
	if (ret)
		return -1;
	if (first)
		lane_wake(lane);
	return 0;
}

int cpa_add_stack_event(struct stack_sample *sample)
{
	struct unwind_lane *lane;
	int ret;

	if (!sample || should_stop() || !cpa_unwind_queue_accepting())
		return -1;

	lane = lane_of_tgid((uint32_t)sample->tgid);
	pthread_mutex_lock(&lane->lock);
	/*
	 * Again under the lane lock: a pause may have closed admission and
	 * drained the lanes since the check above.  A drain takes this lock, so
	 * a sample is either counted before it or refused here.
	 */
	if (should_stop() || !cpa_unwind_queue_accepting()) {
		pthread_mutex_unlock(&lane->lock);
		return -1;
	}
	ret = lane_admit_sample_locked(lane, sample);
	pthread_mutex_unlock(&lane->lock);
	/* from here the sample may already be unwound and freed: not touched */
	return ret;
}
