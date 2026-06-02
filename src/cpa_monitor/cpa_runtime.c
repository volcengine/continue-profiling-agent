// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "cpa_runtime.h"
#include "cli_output.h"
#include "cli_stackmap.h"
#include "cli.h"
#include "cpa_stackmap_continuous.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <unistd.h>
#include <time.h>

struct cpa_cfg {
	int record_interval;
	int persistent_day;
};

struct cpa_runtime {
	struct cpa_cfg cfg;
	int timer_fd;
	int stop_fd;
	time_t next_day_time;
	bool timer_created;

	struct cpa_worker **workers;
	int worker_count;

	pthread_t timer_thread;
	struct cli_stackmap *trace_stackmap;

	bool need_restart;
};

pthread_mutex_t tracemap_lock = PTHREAD_MUTEX_INITIALIZER;

struct cpa_runtime runtime = {
	.timer_fd = -1,
	.stop_fd = -1,
	.workers = NULL,
	.worker_count = 0,
	.need_restart = false,
};

static void *cpa_runtime_timer_thread(void *arg);
static int cpa_runtime_create_timer_thread(void);
static int cpa_runtime_join_timer_thread(void);
static int cpa_runtime_restart_loop(void);
static void update_next_day_timestamp(void);
static void cpa_runtime_wake_timer_thread(void);

static struct cli_stackmap *cpa_runtime_replace_tracemap(struct cli_stackmap *new_map)
{
	struct cli_stackmap *old_map = NULL;

	pthread_mutex_lock(&tracemap_lock);
	old_map = runtime.trace_stackmap;
	runtime.trace_stackmap = new_map;
	pthread_mutex_unlock(&tracemap_lock);

	return old_map;
}

struct cli_stackmap *cpa_main_tracemap_get_and_lock(void)
{
	pthread_mutex_lock(&tracemap_lock);
	return runtime.trace_stackmap;
}

void cpa_main_tracemap_unlock(void)
{
	pthread_mutex_unlock(&tracemap_lock);
}

static int compare_workers(const void *a, const void *b)
{
	const struct cpa_worker *worker_a = *(const struct cpa_worker **)a;
	const struct cpa_worker *worker_b = *(const struct cpa_worker **)b;

	if (worker_a->worker_index < worker_b->worker_index)
		return -1;
	if (worker_a->worker_index > worker_b->worker_index)
		return 1;

	int name_cmp = strncmp(worker_a->worker_name, worker_b->worker_name, sizeof(worker_a->worker_name));
	if (name_cmp != 0)
		return name_cmp;

	if (worker_a < worker_b)
		return -1;
	if (worker_a > worker_b)
		return 1;
	return 0;
}

int cpa_runtime_register(struct cpa_worker **to_register, int count)
{
	if (!to_register || count <= 0) {
		CLI_OUTPUT("Failed to register workers, invalid arguments, to_register: %p, count: %d", to_register, count);
		return -EINVAL;
	}

	int old_count = runtime.worker_count;
	int new_count = old_count + count;

	struct cpa_worker **new_list = calloc(new_count, sizeof(struct cpa_worker *));
	if (!new_list) {
		CLI_OUTPUT("Failed to calloc workers, errno: %d, %s", errno, strerror(errno));
		return -ENOMEM;
	}

	if (runtime.workers)
		memcpy(new_list, runtime.workers, old_count * sizeof(struct cpa_worker *));

	for (int i = 0; i < count; i++) {
		new_list[old_count + i] = to_register[i];
	}

	free(runtime.workers);

	runtime.workers = new_list;
	runtime.worker_count = new_count;

	qsort(runtime.workers, runtime.worker_count, sizeof(struct cpa_worker *), compare_workers);

	return 0;
}

static int cpa_runtime_worker_exec_init(void *cli_ctx)
{
	int i = 0;
	int ret = 0;
	const char **success_names = (const char **)calloc(runtime.worker_count, sizeof(const char *));
	const char **skip_names = (const char **)calloc(runtime.worker_count, sizeof(const char *));
	int success_count = 0, skip_count = 0;

	if (!success_names || !skip_names) {
		free(success_names);
		free(skip_names);
		CLI_ERROR("Failed to alloc memory for init summary");
		return -ENOMEM;
	}

	while (i < runtime.worker_count) {
		struct cpa_worker *worker = runtime.workers[i];
		if (!worker->init_fn) {
			i++;
			continue;
		}

		enum cpa_worker_init_result ret_val = worker->init_fn(cli_ctx, worker->worker_ctx);

		if (ret_val == CPA_INIT_SUCCESS) {
			success_names[success_count++] = worker->worker_name;
			i++;
			continue;
		}

		if (ret_val == CPA_INIT_SKIP) {
			skip_names[skip_count++] = worker->worker_name;
			if (i < runtime.worker_count - 1) {
				memmove(&runtime.workers[i], &runtime.workers[i + 1], (runtime.worker_count - i - 1) * sizeof(struct cpa_worker *));
			}
			runtime.worker_count--;
			/*
			 * Compact skipped workers in place so later runtime loops see
			 * exactly the initialized worker set in dependency order.
			 */
			continue;
		}

		CLI_OUTPUT("Failed to init worker %s, errno: %d, %s", worker->worker_name, ret_val, strerror(ret_val));
		ret = ret_val;
		goto error;
	}

	if (success_count > 0) {
		CLI_OUTPUT("Init SUCCESS workers:");
		CLI_OUTPUT_NO_END("\t[");
		for (int k = 0; k < success_count; k++) {
			CLI_OUTPUT_NO_END("%s%s", success_names[k], (k == success_count - 1) ? "" : ", ");
		}
		CLI_OUTPUT("]");
	} else {
		CLI_OUTPUT("Init SUCCESS workers:\nNone");
	}

	if (skip_count > 0) {
		CLI_OUTPUT("Init SKIP workers:");
		CLI_OUTPUT_NO_END("\t[");
		for (int k = 0; k < skip_count; k++) {
			CLI_OUTPUT_NO_END("%s%s", skip_names[k], (k == skip_count - 1) ? "" : ", ");
		}
		CLI_OUTPUT("]");
	} else {
		CLI_OUTPUT("Init SKIP workers:\nNone");
	}

	free(success_names);
	free(skip_names);
	return 0;

error:
	free(success_names);
	free(skip_names);
	/* Roll back partial startup in reverse init order. */
	for (int j = i - 1; j >= 0; j--) {
		struct cpa_worker *prev_worker = runtime.workers[j];
		if (!prev_worker->destroy_fn)
			continue;
		prev_worker->destroy_fn(prev_worker->worker_ctx);
	}
	return ret;
}

static void cpa_runtime_worker_exec_destroy(void)
{
	/* Late-registered workers are destroyed first to honor dependencies. */
	for (int i = runtime.worker_count - 1; i >= 0; i--) {
		struct cpa_worker *worker = runtime.workers[i];
		if (!worker->destroy_fn)
			continue;
		CLI_OUTPUT("Destroy worker %s.", worker->worker_name);
		worker->destroy_fn(worker->worker_ctx);
	}
}

static int cpa_wait_timer(void)
{
	struct pollfd fds[2];
	fds[0].fd = runtime.timer_fd;
	fds[0].events = POLLIN;
	fds[1].fd = runtime.stop_fd;
	fds[1].events = POLLIN;

	/*
	 * timer_fd drives periodic worker callbacks; stop_fd wakes this thread
	 * during shutdown so stop does not wait for the next timer tick.
	 */
	int n = poll(fds, 2, -1);
	if (n < 0) {
		if (errno == EINTR)
			return 1;
		CLI_ERROR("Failed to poll, errno: %d, %s", errno, strerror(errno));
		return -1;
	}

	if (n == 0)
		return 1;

	if (fds[1].revents & POLLIN) {
		eventfd_t value;
		eventfd_read(runtime.stop_fd, &value);
		return -1;
	}

	if (fds[0].revents & POLLIN) {
		uint64_t exp;
		ssize_t s = read(runtime.timer_fd, &exp, sizeof(uint64_t));
		if (s != sizeof(uint64_t)) {
			CLI_ERROR("Failed to read timer_fd, errno: %d, %s", errno, strerror(errno));
			return -1;
		}
	}

	return 0;
}

void cpa_runtime_need_restart(void)
{
	runtime.need_restart = true;
}

static void *cpa_runtime_timer_thread(void *arg)
{
	while (!should_stop()) {
		int ret = cpa_wait_timer();
		if (ret < 0)
			break;
		if (ret > 0)
			continue;

		for (int i = 0; i < runtime.worker_count; i++) {
			struct cpa_worker *worker = runtime.workers[i];
			if (!worker->timer_fn)
				continue;
			worker->timer_fn(worker->worker_ctx);
		}

		if (time(NULL) > runtime.next_day_time || runtime.need_restart) {
			bool retry_requested = runtime.need_restart;

			/*
			 * Restart work runs after timer callbacks. If a size-limit
			 * restart fails, keep the request set and retry on the next
			 * timer tick instead of dropping the signal.
			 */
			if (runtime.need_restart)
				runtime.need_restart = false;

			if (cpa_runtime_restart_loop() == 0) {
				update_next_day_timestamp();
			} else if (retry_requested) {
				runtime.need_restart = true;
			}
		}
	}
	return NULL;
}

static int cpa_runtime_restart_loop(void)
{
	struct cli_stackmap *old_map = NULL;
	struct cli_stackmap *new_map = NULL;
	int restart_ret = 0;

	/*
	 * Restart is staged: pause producers, flush the old store, create and
	 * commit a new store, swap the shared tracemap, then resume producers.
	 */
	for (int i = runtime.worker_count - 1; i >= 0; i--) {
		struct cpa_worker *worker = runtime.workers[i];
		if (!worker->pause_fn)
			continue;
		worker->pause_fn(worker->worker_ctx);
	}

	restart_ret = cpa_stackmap_continuous_prepare_restart();
	if (restart_ret != 0) {
		CLI_ERROR("Failed to prepare restart store directory");
		goto restore;
	}

	new_map = cli_stackmap_init();
	if (!new_map) {
		CLI_ERROR("Failed to init new trace_stackmap during restart");
		cpa_stackmap_continuous_abort_restart();
		restart_ret = -ENOMEM;
		goto restore;
	}

	restart_ret = cpa_stackmap_continuous_commit_restart();
	if (restart_ret != 0) {
		CLI_ERROR("Failed to commit restart store directory");
		cli_stackmap_destroy(new_map);
		new_map = NULL;
		cpa_stackmap_continuous_abort_restart();
		goto restore;
	}

	old_map = cpa_runtime_replace_tracemap(new_map);

restore:
	for (int i = 0; i < runtime.worker_count; i++) {
		struct cpa_worker *worker = runtime.workers[i];
		if (!worker->restore_fn)
			continue;
		worker->restore_fn(worker->worker_ctx);
	}

	if (old_map)
		cli_stackmap_destroy(old_map);

	return restart_ret;
}

static void update_next_day_timestamp(void)
{
	time_t now = time(NULL);
	struct tm *now_tm = localtime(&now);

	now_tm->tm_mday += 1;
	now_tm->tm_hour = 0;
	now_tm->tm_min = 0;
	now_tm->tm_sec = 0;

	runtime.next_day_time = mktime(now_tm);
}

int cpa_runtime_start(void *cli_ctx)
{
	if (!cli_ctx) {
		CLI_OUTPUT("Failed to start runtime, cli_ctx: %p", cli_ctx);
		return -EINVAL;
	}

	runtime.cfg.record_interval = atoi(get_arg_by_name(cli_ctx, "record_interval"));
	runtime.cfg.persistent_day = atoi(get_arg_by_name(cli_ctx, "persistent_day"));
	if (runtime.cfg.record_interval <= 0) {
		CLI_ERROR("record_interval must be positive");
		return -EINVAL;
	}
	if (runtime.cfg.persistent_day <= 0) {
		CLI_ERROR("Please use persistent_day > 0");
		return -EINVAL;
	}

	runtime.trace_stackmap = cli_stackmap_init();
	if (!runtime.trace_stackmap) {
		CLI_ERROR("Failed to init trace_stackmap");
		return EXIT_FAILURE;
	}

	int ret = cpa_runtime_worker_exec_init(cli_ctx);
	if (ret) {
		cli_stackmap_destroy(runtime.trace_stackmap);
		runtime.trace_stackmap = NULL;
		return ret;
	}

	update_next_day_timestamp();

	if (cpa_runtime_create_timer_thread() != 0) {
		cpa_runtime_worker_exec_destroy();
		cli_stackmap_destroy(runtime.trace_stackmap);
		runtime.trace_stackmap = NULL;
		return EXIT_FAILURE;
	}

	return 0;
}

int cpa_runtime_stop(void)
{
	struct cli_stackmap *old_map = NULL;

	/* Wake and join timer thread before worker teardown touches timer state. */
	cpa_runtime_wake_timer_thread();
	if (cpa_runtime_join_timer_thread() != 0)
		return EXIT_FAILURE;

	cpa_runtime_worker_exec_destroy();

	old_map = cpa_runtime_replace_tracemap(NULL);
	if (old_map)
		cli_stackmap_destroy(old_map);

	return 0;
}

void cpa_runtime_loop(void)
{
	while (1) {
		bool had_main_worker = false;

		for (int i = 0; i < runtime.worker_count; i++) {
			struct cpa_worker *worker = runtime.workers[i];
			if (!worker->main_worker_fn)
				continue;
			had_main_worker = true;
			worker->main_worker_fn(worker->worker_ctx);
		}
		if (!had_main_worker)
			usleep(1000);
		if (should_stop())
			break;
	}
}

static int cpa_runtime_create_timer_thread(void)
{
	runtime.timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
	if (runtime.timer_fd < 0) {
		CLI_ERROR("Failed to create timer_fd, errno: %d, %s", errno, strerror(errno));
		return -1;
	}

	runtime.stop_fd = eventfd(0, EFD_CLOEXEC);
	if (runtime.stop_fd < 0) {
		CLI_ERROR("Failed to create stop_fd, errno: %d, %s", errno, strerror(errno));
		close(runtime.timer_fd);
		runtime.timer_fd = -1;
		return -1;
	}

	struct itimerspec its;
	its.it_value.tv_sec = runtime.cfg.record_interval;
	its.it_value.tv_nsec = 0;
	its.it_interval.tv_sec = runtime.cfg.record_interval;
	its.it_interval.tv_nsec = 0;

	if (timerfd_settime(runtime.timer_fd, 0, &its, NULL) < 0) {
		CLI_ERROR("Failed to set timer_fd, errno: %d, %s", errno, strerror(errno));
		close(runtime.timer_fd);
		runtime.timer_fd = -1;
		close(runtime.stop_fd);
		runtime.stop_fd = -1;
		return -1;
	}

	if (pthread_create(&runtime.timer_thread, NULL, cpa_runtime_timer_thread, NULL) != 0) {
		CLI_ERROR("Failed to create timer_thread");
		close(runtime.timer_fd);
		runtime.timer_fd = -1;
		close(runtime.stop_fd);
		runtime.stop_fd = -1;
		return -1;
	}
	runtime.timer_created = true;
	return 0;
}

static void cpa_runtime_wake_timer_thread(void)
{
	if (runtime.stop_fd >= 0)
		eventfd_write(runtime.stop_fd, 1);
}

static int cpa_runtime_join_timer_thread(void)
{
	if (!runtime.timer_created) {
		return -1;
	}

	if (pthread_join(runtime.timer_thread, NULL) != 0) {
		CLI_ERROR("Failed to join timer_thread");
		return -1;
	}
	runtime.timer_created = false;

	close(runtime.timer_fd);
	runtime.timer_fd = -1;
	close(runtime.stop_fd);
	runtime.stop_fd = -1;
	return 0;
}
