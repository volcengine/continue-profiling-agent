// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "cpa_exit_env.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "cli_output.h"
#include "uthash.h"

#include <fcntl.h>
#include <unistd.h>

/* selections waiting for the reader, and those to read again; more are dropped */
#define EXIT_ENV_QUEUE_CAP 1024U
/* a live process without an environ yet: read again, this often, this apart */
#define EXIT_ENV_READ_TRIES 5
#define EXIT_ENV_RETRY_NS (10 * 1000000ULL)

struct exit_env_key {
	uint32_t tgid;
	uint32_t pad;
	uint64_t identity;
};

struct exit_env_entry {
	struct exit_env_key key;
	bool match;
	UT_hash_handle hh;
};

static struct cpa_exit_spec cond;
static int n_names;

static pthread_mutex_t table_lock = PTHREAD_MUTEX_INITIALIZER;
static struct exit_env_entry *table;
static bool full_reported;

struct exit_env_item {
	struct exit_env_key key;
	uint64_t due_ns;	/* CLOCK_MONOTONIC; the retry ring only */
	int tries;
};

/* a FIFO; the retry ring is in due order, since every delay is the same */
struct exit_env_ring {
	struct exit_env_item items[EXIT_ENV_QUEUE_CAP];
	unsigned int head, len;
};

static pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_cond;	/* on CLOCK_MONOTONIC, set up at start */
static struct exit_env_ring fresh, retry;
static bool reader_stopping, reader_started;
static pthread_t reader;

static struct exit_env_key key_of(uint32_t tgid, uint64_t identity)
{
	struct exit_env_key key = { .tgid = tgid, .identity = identity };

	return key;
}

void cpa_exit_env_configure(const struct cpa_exit_spec *spec)
{
	cond = *spec;
	n_names = spec->n_env_names;
}

bool cpa_exit_env_enabled(void)
{
	return n_names > 0;
}

bool cpa_exit_env_value_matches(const char *value)
{
	for (int i = 0; i < cond.n_env_values; i++)
		if (strcmp(value, cond.env_values[i]) == 0)
			return true;
	for (int i = 0; i < cond.n_env_prefixes; i++)
		if (strncmp(value, cond.env_prefixes[i],
			    strlen(cond.env_prefixes[i])) == 0)
			return true;
	return false;
}

/* environ beyond this is not looked at (the kernel caps argv+envp lower) */
#define EXIT_ENV_READ_MAX (4U << 20)

int cpa_exit_env_lookup(uint32_t pid, char *const *names, int count, char **value)
{
	char path[64];
	char *buf = NULL;
	size_t len = 0, cap = 0;
	int fd, best = count;

	*value = NULL;
	snprintf(path, sizeof(path), "/proc/%u/environ", pid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	for (;;) {
		ssize_t n;

		if (len == cap) {
			char *grown;

			if (cap >= EXIT_ENV_READ_MAX)
				break;
			cap = cap ? cap * 2 : 4096;
			grown = realloc(buf, cap + 1);
			if (!grown) {
				free(buf);
				close(fd);
				return -1;
			}
			buf = grown;
		}
		n = read(fd, buf + len, cap - len);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		len += (size_t)n;
	}
	close(fd);
	/* empty: gone, past exit_mm(), or mid exec */
	if (!len) {
		free(buf);
		return -1;
	}
	buf[len] = '\0';
	/* the first listed name that is set, whatever the environ's order */
	for (char *v = buf; v < buf + len; v += strlen(v) + 1) {
		for (int i = 0; i < best; i++) {
			size_t nl = strlen(names[i]);

			if (strncmp(v, names[i], nl) == 0 && v[nl] == '=' && v[nl + 1]) {
				free(*value);
				*value = strdup(v + nl + 1);
				best = i;
				break;
			}
		}
	}
	free(buf);
	return 0;
}

/*
 * 0 with @match set; -1: gone, or no environ yet (mid exec) or any more
 * (past exit_mm).  The value is the first listed name that is set.
 */
static int read_verdict(uint32_t tgid, bool *match)
{
	char *name_ptrs[CPA_EXIT_MAX_ENV_NAMES];
	char *value = NULL;
	int ret;

	for (int i = 0; i < n_names; i++)
		name_ptrs[i] = cond.env_names[i];
	ret = cpa_exit_env_lookup(tgid, name_ptrs, n_names, &value);
	*match = ret == 0 && value && cpa_exit_env_value_matches(value);
	free(value);
	return ret;
}

/* At capacity only: drop the instances whose process is gone. */
static void sweep_locked(void)
{
	struct exit_env_entry *e, *tmp;

	HASH_ITER(hh, table, e, tmp) {
		if (kill((pid_t)e->key.tgid, 0) == 0 || errno == EPERM)
			continue;
		HASH_DEL(table, e);
		free(e);
	}
}

bool cpa_exit_env_read(uint32_t tgid, uint64_t identity)
{
	struct exit_env_key key = key_of(tgid, identity);
	struct exit_env_entry *e;
	bool match;

	if (!n_names)
		return true;
	if (read_verdict(tgid, &match))
		return false;

	pthread_mutex_lock(&table_lock);
	HASH_FIND(hh, table, &key, sizeof(key), e);
	if (!e && HASH_COUNT(table) >= CPA_EXIT_ENV_MAX_ENTRIES)
		sweep_locked();
	if (!e && HASH_COUNT(table) < CPA_EXIT_ENV_MAX_ENTRIES) {
		e = calloc(1, sizeof(*e));
		if (e) {
			e->key = key;
			HASH_ADD(hh, table, key, sizeof(key), e);
		}
	}
	if (e) {
		/* exec again under a name: its new environment */
		e->match = match;
	} else if (!full_reported) {
		full_reported = true;
		CLI_ERROR("cpa exit env: %u live processes recorded; "
			  "the exits of newer ones are dropped",
			  CPA_EXIT_ENV_MAX_ENTRIES);
	}
	pthread_mutex_unlock(&table_lock);
	return true;
}

enum cpa_exit_env_verdict cpa_exit_env_verdict(uint32_t tgid,
							  uint64_t identity)
{
	struct exit_env_key key = key_of(tgid, identity);
	struct exit_env_entry *e;
	enum cpa_exit_env_verdict verdict = CPA_EXIT_ENV_UNKNOWN;

	pthread_mutex_lock(&table_lock);
	HASH_FIND(hh, table, &key, sizeof(key), e);
	if (e)
		verdict = e->match ? CPA_EXIT_ENV_MATCH :
				     CPA_EXIT_ENV_MISMATCH;
	pthread_mutex_unlock(&table_lock);
	return verdict;
}

void cpa_exit_env_on_pid_exit(uint32_t tgid, uint64_t identity)
{
	struct exit_env_key key = key_of(tgid, identity);
	struct exit_env_entry *e;

	if (!n_names)
		return;
	pthread_mutex_lock(&table_lock);
	HASH_FIND(hh, table, &key, sizeof(key), e);
	if (e) {
		HASH_DEL(table, e);
		free(e);
	}
	pthread_mutex_unlock(&table_lock);
}

unsigned int cpa_exit_env_count(void)
{
	unsigned int n;

	pthread_mutex_lock(&table_lock);
	n = HASH_COUNT(table);
	pthread_mutex_unlock(&table_lock);
	return n;
}

static uint64_t mono_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static bool ring_push(struct exit_env_ring *r, struct exit_env_item item)
{
	if (r->len >= EXIT_ENV_QUEUE_CAP)
		return false;
	r->items[(r->head + r->len) % EXIT_ENV_QUEUE_CAP] = item;
	r->len++;
	return true;
}

static struct exit_env_item ring_pop(struct exit_env_ring *r)
{
	struct exit_env_item item = r->items[r->head];

	r->head = (r->head + 1) % EXIT_ENV_QUEUE_CAP;
	r->len--;
	return item;
}

/*
 * The next item to read, fresh selections first; false once stopping.  A
 * retry waits for its due time without holding up a fresh one.
 */
static bool reader_next(struct exit_env_item *item)
{
	bool ok = false;

	pthread_mutex_lock(&queue_lock);
	while (!reader_stopping) {
		if (fresh.len) {
			*item = ring_pop(&fresh);
			ok = true;
			break;
		}
		if (retry.len && retry.items[retry.head].due_ns <= mono_ns()) {
			*item = ring_pop(&retry);
			ok = true;
			break;
		}
		if (retry.len) {
			uint64_t due = retry.items[retry.head].due_ns;
			struct timespec until = {
				.tv_sec = (time_t)(due / 1000000000ULL),
				.tv_nsec = (long)(due % 1000000000ULL),
			};

			pthread_cond_timedwait(&queue_cond, &queue_lock, &until);
		} else {
			pthread_cond_wait(&queue_cond, &queue_lock);
		}
	}
	pthread_mutex_unlock(&queue_lock);
	return ok;
}

/*
 * The events arrive on the thread that polls every BPF buffer, which must
 * not wait on a process' mm (reading environ takes it): read here instead.
 *
 * An exec told by the kretprobe/setup_new_exec fallback (4.14, when another
 * program owns sched_process_exec) comes before the loader sets up the new
 * environ, so the first read can find none.  A process that is still there
 * is read again later, a few times; one that is gone is not.  A process
 * whose environ never comes (an empty envp, a zombie) costs a few reads,
 * never a wait in front of the next selection.
 */
static void *reader_main(void *arg)
{
	struct exit_env_item item;

	(void)arg;
	while (reader_next(&item)) {
		if (cpa_exit_env_read(item.key.tgid, item.key.identity) ||
		    ++item.tries >= EXIT_ENV_READ_TRIES ||
		    (kill((pid_t)item.key.tgid, 0) && errno == ESRCH))
			continue;
		item.due_ns = mono_ns() + EXIT_ENV_RETRY_NS;
		pthread_mutex_lock(&queue_lock);
		ring_push(&retry, item);
		pthread_mutex_unlock(&queue_lock);
	}
	return NULL;
}

void cpa_exit_env_selected(uint32_t tgid, uint64_t identity)
{
	struct exit_env_item item = { .key = key_of(tgid, identity) };

	pthread_mutex_lock(&queue_lock);
	if (reader_started && ring_push(&fresh, item))
		pthread_cond_signal(&queue_cond);
	pthread_mutex_unlock(&queue_lock);
}

int cpa_exit_env_start(void)
{
	pthread_condattr_t attr;
	int ret;

	if (!n_names || reader_started)
		return 0;
	reader_stopping = false;
	fresh.head = fresh.len = 0;
	retry.head = retry.len = 0;
	pthread_condattr_init(&attr);
	pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
	pthread_cond_init(&queue_cond, &attr);
	pthread_condattr_destroy(&attr);
	ret = pthread_create(&reader, NULL, reader_main, NULL);
	if (ret) {
		pthread_cond_destroy(&queue_cond);
		return -ret;
	}
	pthread_mutex_lock(&queue_lock);
	reader_started = true;
	pthread_mutex_unlock(&queue_lock);
	return 0;
}

void cpa_exit_env_stop(void)
{
	struct exit_env_entry *e, *tmp;

	if (reader_started) {
		pthread_mutex_lock(&queue_lock);
		reader_stopping = true;
		pthread_cond_broadcast(&queue_cond);
		pthread_mutex_unlock(&queue_lock);
		pthread_join(reader, NULL);
		pthread_mutex_lock(&queue_lock);
		reader_started = false;
		fresh.len = retry.len = 0;
		pthread_mutex_unlock(&queue_lock);
		pthread_cond_destroy(&queue_cond);
	}

	pthread_mutex_lock(&table_lock);
	HASH_ITER(hh, table, e, tmp) {
		HASH_DEL(table, e);
		free(e);
	}
	full_reported = false;
	pthread_mutex_unlock(&table_lock);
}
