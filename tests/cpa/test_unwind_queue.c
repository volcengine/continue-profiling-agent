// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

/*
 * Unit test of the unwind queue (src/cpa_monitor/cpa_unwind_queue.c) and
 * the per-sample frame buffer (cpa_frames.c), linked with the real sample
 * pool, drop policy and ring; the stop flag and the log are stubbed here.
 */

#include "cpa_unwind_queue.h"
#include "cpa_frames.h"
#include "cpa_sample_pool.h"

#include <assert.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ---- stubs ------------------------------------------------------------ */

static atomic_int stop_flag;
static void (*_Atomic stop_hook)(void);

int should_stop(void)
{
	return atomic_load(&stop_flag);
}

void set_stop(void)
{
	void (*fn)(void);

	atomic_store(&stop_flag, 1);
	fn = atomic_load(&stop_hook);
	if (fn)
		fn();
}

int set_stop_notify(void (*fn)(void))
{
	void (*none)(void) = NULL;

	if (atomic_compare_exchange_strong(&stop_hook, &none, fn) || none == fn)
		return 0;
	return -16;
}

void clear_stop_notify(void (*fn)(void))
{
	void (*mine)(void) = fn;

	atomic_compare_exchange_strong(&stop_hook, &mine, NULL);
}

void cli_raw_output(int level, bool end, const char *format, ...)
{
	va_list ap;

	(void)level;
	(void)end;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	fputc('\n', stderr);
}

/* cpa_frames_commit() appends to a stack map: recorded here instead */
static char committed[16][64];
static int committed_len;

int cli_stackmap_append(struct cli_stackmap *map, const char *frame)
{
	(void)map;
	if (committed_len < 16)
		snprintf(committed[committed_len++], sizeof(committed[0]), "%s", frame);
	return 0;
}

/* ---- helpers ---------------------------------------------------------- */

#define CHECK(cond)                                                                    \
	do {                                                                           \
		if (!(cond)) {                                                         \
			fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #cond); \
			exit(1);                                                       \
		}                                                                      \
	} while (0)

static uint64_t now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static struct stack_sample *new_sample(int tgid, uint64_t unique_id)
{
	struct stack_sample *s = cpa_sample_zalloc(sizeof(*s) + sizeof(struct gu_stack_info));

	CHECK(s);
	s->info = (struct gu_stack_info *)(s + 1);
	stack_sample_set_process(s, tgid, tgid);
	s->info->unique_id = unique_id;
	return s;
}

static struct exit_event *new_exit(int tgid, uint64_t unique_id, uint64_t exit_ts)
{
	struct exit_event *e = calloc(1, sizeof(*e));

	CHECK(e);
	e->exit_ts = exit_ts;
	e->gu.pid = tgid;
	e->gu.start_time = unique_id;
	return e;
}

/* a tgid of @lane, at most @nth found */
static int tgid_in_lane(unsigned int lane, int nth)
{
	for (int t = 100;; t++)
		if (cpa_unwind_lane_of((uint32_t)t) == lane && nth-- == 0)
			return t;
}

static void start(int queue_size, unsigned int lanes)
{
	atomic_store(&stop_flag, 0);
	CHECK(cpa_unwind_queue_init(queue_size, lanes) == 0);
	cpa_unwind_queue_set_accepting(true);
}

static void finish(void)
{
	cpa_unwind_queue_set_accepting(false);
	cpa_unwind_queue_cleanup(true);
}

/* ---- tests ------------------------------------------------------------ */

static void test_parse(void)
{
	unsigned int n = 0;

	CHECK(cpa_unwind_workers_parse("4", 8, &n) == 0 && n == 4);
	CHECK(cpa_unwind_workers_parse("8", 8, &n) == 0 && n == 8);
	CHECK(cpa_unwind_workers_parse("9", 8, &n) == -ERANGE);
	CHECK(cpa_unwind_workers_parse("0", 8, &n) == -ERANGE);
	CHECK(cpa_unwind_workers_parse("", 8, &n) == -EINVAL);
	CHECK(cpa_unwind_workers_parse("2x", 8, &n) == -EINVAL);
	CHECK(cpa_unwind_workers_parse("-1", 8, &n) == -EINVAL);
	CHECK(cpa_unwind_workers_parse("99999999999999999999", 8, &n) == -ERANGE);
}

/* a process' samples and its exit go to one lane; one lane needs no hash */
static void test_routing(void)
{
	start(64, 4);
	CHECK(cpa_unwind_queue_lanes() == 4);
	for (int t = 1; t < 2000; t++)
		CHECK(cpa_unwind_lane_of((uint32_t)t) < 4);
	int t = tgid_in_lane(2, 0);
	CHECK(cpa_add_stack_event(new_sample(t, 7)) == 0);
	CHECK(cpa_unwind_queue_pop_sample(0) == NULL);
	CHECK(cpa_unwind_queue_pop_sample(1) == NULL);
	struct stack_sample *s = cpa_unwind_queue_pop_sample(2);
	CHECK(s && s->tgid == t);
	cpa_unwind_queue_retire_sample(s);
	finish();

	start(64, 1);
	CHECK(cpa_unwind_lane_of(12345) == 0);
	finish();
}

/*
 * Admission: queued plus worker-held samples never exceed queue_size - 1 +
 * lanes, and one busy process is refused no earlier than with one lane.
 */
static void test_admission(void)
{
	const int size = 16;
	unsigned int ok = 0;

	start(size, 4);
	int t = tgid_in_lane(1, 0);
	struct stack_sample *refused;

	while ((refused = new_sample(t, 1)) && cpa_add_stack_event(refused) == 0)
		ok++;
	/* the refused one was not taken: the caller still owns it */
	cpa_sample_free(refused);
	/* one lane's ring: size - 1 */
	CHECK(ok == size - 1);

	/* other lanes still get the rest of the budget, then it is full */
	unsigned int more = 0;
	for (unsigned int l = 0; l < 4; l++) {
		if (l == 1)
			continue;
		int u = tgid_in_lane(l, 0);
		struct stack_sample *s;

		while ((s = new_sample(u, 1)) && cpa_add_stack_event(s) == 0)
			more++;
		cpa_sample_free(s);
	}
	CHECK(ok + more == size - 1 + 4);
	CHECK(cpa_unwind_queue_admitted() == size - 1 + 4);
	CHECK(cpa_unwind_queue_pending_samples() == size - 1 + 4);

	/* a popped (worker-held) sample keeps its credit until retired */
	struct stack_sample *held = cpa_unwind_queue_pop_sample(1);
	CHECK(held);
	CHECK(cpa_unwind_queue_admitted() == size - 1 + 4);
	cpa_unwind_queue_retire_sample(held);
	CHECK(cpa_unwind_queue_admitted() == size - 1 + 4 - 1);
	finish();
	CHECK(cpa_unwind_queue_admitted() == 0);
}

/*
 * An exit is reaped after its grace period, and not while a sample of its
 * instance is queued or being unwound: the last sample releases it.  An
 * exit of another instance of the same tgid is not held.
 */
static void test_exit_waits_for_its_samples(void)
{
	struct exit_event *out[8];
	uint64_t deadline = 0;
	int t = 4242;

	start(64, 1);
	CHECK(cpa_add_stack_event(new_sample(t, 7)) == 0);
	CHECK(cpa_add_stack_event(new_sample(t, 7)) == 0);
	/* long past its grace period */
	CHECK(cpa_add_pid_exit_event(new_exit(t, 7, 1)) == 0);
	CHECK(cpa_add_pid_exit_event(new_exit(t, 8, 1)) == 0);
	CHECK(cpa_unwind_queue_exit_len() == 2);

	/* instance 8 has no samples: ready; instance 7 parks */
	CHECK(cpa_unwind_queue_pop_ready_exits(0, out, 8, &deadline) == 1);
	CHECK(out[0]->gu.start_time == 8);
	free(out[0]);
	CHECK(cpa_unwind_queue_pop_ready_exits(0, out, 8, &deadline) == 0);

	struct stack_sample *a = cpa_unwind_queue_pop_sample(0);
	struct stack_sample *b = cpa_unwind_queue_pop_sample(0);
	cpa_unwind_queue_retire_sample(a);
	CHECK(cpa_unwind_queue_pop_ready_exits(0, out, 8, &deadline) == 0);
	cpa_unwind_queue_retire_sample(b);
	CHECK(cpa_unwind_queue_pop_ready_exits(0, out, 8, &deadline) == 1);
	CHECK(out[0]->gu.pid == t && out[0]->gu.start_time == 7);
	free(out[0]);

	/* within the grace period: not ready, a deadline is given */
	CHECK(cpa_add_pid_exit_event(new_exit(t, 9, now_ns())) == 0);
	CHECK(cpa_unwind_queue_pop_ready_exits(0, out, 8, &deadline) == 0);
	CHECK(deadline > now_ns());
	finish();
}

/* the lanes share one exit capacity, wherever the exits hash */
static void test_exit_capacity_is_shared(void)
{
	unsigned int ok = 0;
	struct exit_event *e;

	start(16, 4);
	int t = tgid_in_lane(3, 0);
	while ((e = new_exit(t, ok, now_ns())) && cpa_add_pid_exit_event(e) == 0)
		ok++;
	free(e);
	CHECK(ok == 32767);
	int u = tgid_in_lane(0, 0);
	e = new_exit(u, 1, now_ns());
	CHECK(cpa_add_pid_exit_event(e) != 0);
	free(e);
	finish();
	CHECK(cpa_unwind_queue_exit_len() == 0);
}

struct waiter {
	unsigned int lane;
	uint64_t deadline;
	atomic_int woke;
	struct stack_sample *got;
};

static void *wait_main(void *arg)
{
	struct waiter *w = arg;

	w->got = cpa_unwind_queue_wait_sample(w->lane, w->deadline);
	atomic_store(&w->woke, 1);
	return NULL;
}

static bool woke_within(struct waiter *w, int ms)
{
	for (int i = 0; i < ms; i++) {
		if (atomic_load(&w->woke))
			return true;
		usleep(1000);
	}
	return atomic_load(&w->woke);
}

/* a sample wakes its own lane only; a stop wakes every lane */
static void test_wakeups(void)
{
	struct waiter w[3] = { { .lane = 0 }, { .lane = 1 }, { .lane = 2 } };
	pthread_t th[3];

	start(64, 3);
	for (int i = 0; i < 3; i++)
		pthread_create(&th[i], NULL, wait_main, &w[i]);
	usleep(50000);
	CHECK(cpa_add_stack_event(new_sample(tgid_in_lane(1, 0), 1)) == 0);
	CHECK(woke_within(&w[1], 2000));
	CHECK(w[1].got != NULL);
	cpa_unwind_queue_retire_sample(w[1].got);
	usleep(50000);
	CHECK(!atomic_load(&w[0].woke) && !atomic_load(&w[2].woke));

	set_stop();
	CHECK(woke_within(&w[0], 2000) && woke_within(&w[2], 2000));
	for (int i = 0; i < 3; i++)
		pthread_join(th[i], NULL);
	CHECK(w[0].got == NULL && w[2].got == NULL);
	finish();
}

/*
 * The first exit of an empty lane wakes a worker that sleeps with no
 * deadline, every time: run the race many times.
 */
static void test_first_exit_wakes_the_worker(void)
{
	start(64, 2);
	for (int round = 0; round < 2000; round++) {
		struct waiter w = { .lane = 1 };
		struct exit_event *out[2];
		uint64_t deadline;
		pthread_t th;

		pthread_create(&th, NULL, wait_main, &w);
		if (round & 1)
			usleep(100);
		CHECK(cpa_add_pid_exit_event(new_exit(tgid_in_lane(1, 0), round, 1)) == 0);
		CHECK(woke_within(&w, 2000));
		pthread_join(th, NULL);
		CHECK(cpa_unwind_queue_pop_ready_exits(1, out, 2, &deadline) == 1);
		free(out[0]);
	}
	finish();
}

/* closed admission is checked again under the lane lock */
static void test_closed_admission(void)
{
	start(64, 2);
	cpa_unwind_queue_set_accepting(false);
	struct stack_sample *s = new_sample(1, 1);
	CHECK(cpa_add_stack_event(s) != 0);
	cpa_sample_free(s);
	struct exit_event *e = new_exit(1, 1, 1);
	CHECK(cpa_add_pid_exit_event(e) != 0);
	free(e);
	finish();
}

/* cpa_frames mirrors a stack map entry: append, reset, reverse */
static void test_frames(void)
{
	struct cpa_frames f;
	char long_frame[9000];

	cpa_frames_init(&f);
	cpa_frames_append(&f, "meta");
	cpa_frames_reverse(&f);
	uint32_t mark = cpa_frames_length(&f);
	cpa_frames_append(&f, "dwarf1");
	cpa_frames_append(&f, "dwarf2");
	cpa_frames_reset(&f, mark);
	cpa_frames_append(&f, "u1");
	cpa_frames_append(&f, "u2");
	cpa_frames_append(&f, "u3");
	cpa_frames_reverse(&f);
	cpa_frames_append(&f, "k1");
	cpa_frames_append(&f, "k2");
	cpa_frames_reverse(&f);
	const char *want[] = { "meta", "u3", "u2", "u1", "k2", "k1" };
	CHECK(cpa_frames_length(&f) == 6);
	for (uint32_t i = 0; i < 6; i++)
		CHECK(strcmp(f.text + f.offsets[i], want[i]) == 0);

	/* the commit appends in final order */
	committed_len = 0;
	cpa_frames_commit(&f, NULL);
	CHECK(committed_len == 6);
	for (int i = 0; i < 6; i++)
		CHECK(strcmp(committed[i], want[i]) == 0);

	/* a reset past the end changes nothing */
	cpa_frames_reset(&f, 99);
	CHECK(cpa_frames_length(&f) == 6);

	/* truncated like the stack map */
	memset(long_frame, 'x', sizeof(long_frame) - 1);
	long_frame[sizeof(long_frame) - 1] = '\0';
	cpa_frames_clear(&f);
	cpa_frames_append(&f, long_frame);
	CHECK(strlen(f.text + f.offsets[0]) == CLI_STACKMAP_FRAME_MAX_LEN);
	cpa_frames_destroy(&f);
}

int main(void)
{
	test_parse();
	test_routing();
	test_admission();
	test_exit_waits_for_its_samples();
	test_exit_capacity_is_shared();
	test_wakeups();
	test_first_exit_wakes_the_worker();
	test_closed_admission();
	test_frames();
	printf("unwind queue ok\n");
	return 0;
}
