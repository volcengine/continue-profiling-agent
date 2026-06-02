// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "bpf_event_poll.h"
#include "core.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <linux/kernel.h>
#include <linux/list.h>

#define MAX_EVENTS 100
static atomic_int g_epoll_fd;
_Atomic bool g_stop;
static pthread_t g_poll_thread;
static atomic_bool g_poll_thread_started;
static atomic_uint g_inflight_events;

static pthread_mutex_t pb_ctx_list_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t pb_ctx_list_cond = PTHREAD_COND_INITIALIZER;
static LIST_HEAD(pb_ctx_list);
static LIST_HEAD(pb_ctx_ref_list);
static atomic_ullong g_lost_events;

struct perf_event_handler_ctx;

struct perf_event_epoll_ref {
	struct perf_event_handler_ctx *_Atomic ctx;
	struct list_head list;
};

struct perf_event_handler_ctx {
	int perf_map_fd;
	struct perf_buffer *pb;
	bpf_event_process_fn handler;
	_Atomic unsigned int active_consumers;
	_Atomic bool detaching;
	struct perf_event_epoll_ref *ref;
	struct list_head list;
};

static void perf_event_ctx_release_consumer(struct perf_event_handler_ctx *ctx)
{
	unsigned int active = 0;

	active = atomic_fetch_sub_explicit(&ctx->active_consumers, 1, memory_order_acq_rel);
	if (active == 1) {
		pthread_mutex_lock(&pb_ctx_list_lock);
		pthread_cond_broadcast(&pb_ctx_list_cond);
		pthread_mutex_unlock(&pb_ctx_list_lock);
	}
}

static struct perf_event_handler_ctx *perf_event_ctx_try_acquire(struct perf_event_epoll_ref *ref)
{
	struct perf_event_handler_ctx *ctx = NULL;

	if (!ref)
		return NULL;

	pthread_mutex_lock(&pb_ctx_list_lock);
	ctx = atomic_load_explicit(&ref->ctx, memory_order_acquire);
	if (!ctx || atomic_load_explicit(&g_stop, memory_order_acquire) || atomic_load_explicit(&ctx->detaching, memory_order_acquire) || !ctx->handler) {
		ctx = NULL;
		goto out;
	}

	atomic_fetch_add_explicit(&ctx->active_consumers, 1, memory_order_acq_rel);

out:
	pthread_mutex_unlock(&pb_ctx_list_lock);
	return ctx;
}

static void perf_event_ctx_mark_detaching(struct perf_event_handler_ctx *ctx)
{
	if (!ctx)
		return;

	atomic_store_explicit(&ctx->detaching, true, memory_order_release);
	if (ctx->ref)
		atomic_store_explicit(&ctx->ref->ctx, NULL, memory_order_release);
}

static void *poll_event_thread(void *arg)
{
	int epoll_fd = -1;
	int event_count, i, ret;
	struct epoll_event events[MAX_EVENTS];
	struct perf_event_epoll_ref *ref = NULL;
	struct perf_event_handler_ctx *pb_ctx = NULL;

	epoll_fd = epoll_create1(0);
	if (epoll_fd == -1) {
		BPF_ERR("epoll_create failed errno=%d\n", errno);
		goto end;
	}
	atomic_store_explicit(&g_epoll_fd, epoll_fd, memory_order_release);

	while (!atomic_load_explicit(&g_stop, memory_order_acquire)) {
		event_count = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
		if (event_count < 0) {
			if (atomic_load_explicit(&g_stop, memory_order_acquire) || errno == EBADF)
				break;
			if (errno == EINTR)
				continue;
			BPF_ERR("epoll_wait failed errno=%d\n", errno);
			goto end;
		}

		for (i = 0; i < event_count && !atomic_load_explicit(&g_stop, memory_order_acquire); i++) {
			ref = (struct perf_event_epoll_ref *)events[i].data.ptr;
			pb_ctx = perf_event_ctx_try_acquire(ref);
			if (!pb_ctx)
				continue;
			atomic_fetch_add_explicit(&g_inflight_events, 1, memory_order_acq_rel);

			ret = perf_buffer__consume(pb_ctx->pb);
			atomic_fetch_sub_explicit(&g_inflight_events, 1, memory_order_acq_rel);
			perf_event_ctx_release_consumer(pb_ctx);

			if (ret < 0)
				BPF_WARN("perf buffer consume failed ret=%d\n", ret);
		}
	}

end:
	epoll_fd = atomic_exchange_explicit(&g_epoll_fd, -1, memory_order_acq_rel);
	if (epoll_fd != -1)
		close(epoll_fd);

	return NULL;
}

int bpf_event_poll_init(void)
{
	if (atomic_load_explicit(&g_poll_thread_started, memory_order_acquire)) {
		BPF_WARN("bpf_event_poll already inited\n");
		return -1;
	}

	atomic_store_explicit(&g_stop, false, memory_order_release);
	atomic_store_explicit(&g_lost_events, 0, memory_order_relaxed);
	atomic_store_explicit(&g_inflight_events, 0, memory_order_relaxed);
	atomic_store_explicit(&g_epoll_fd, -1, memory_order_release);

	INIT_LIST_HEAD(&pb_ctx_list);
	INIT_LIST_HEAD(&pb_ctx_ref_list);

	if (pthread_create(&g_poll_thread, NULL, poll_event_thread, NULL) != 0) {
		BPF_ERR("failed to create poll thread\n");
		return -1;
	}
	atomic_store_explicit(&g_poll_thread_started, true, memory_order_release);

	int i;
	for (i = 0; i < 1000; i++) {
		if (atomic_load_explicit(&g_epoll_fd, memory_order_acquire) != -1)
			break;
		usleep(1000);
	}
	if (atomic_load_explicit(&g_epoll_fd, memory_order_acquire) == -1) {
		atomic_store_explicit(&g_stop, true, memory_order_release);
		pthread_join(g_poll_thread, NULL);
		atomic_store_explicit(&g_poll_thread_started, false, memory_order_release);
		BPF_ERR("failed to init bpf_event_poll\n");
		return -1;
	}

	return 0;
}

void bpf_event_poll_destroy(void)
{
	struct perf_event_handler_ctx *ctx = NULL;
	struct perf_event_epoll_ref *ref = NULL;
	int epoll_fd = -1;

	atomic_store_explicit(&g_stop, true, memory_order_release);
	epoll_fd = atomic_exchange_explicit(&g_epoll_fd, -1, memory_order_acq_rel);
	if (epoll_fd != -1)
		close(epoll_fd);

	pthread_mutex_lock(&pb_ctx_list_lock);
	list_for_each_entry(ctx, &pb_ctx_list, list)
	{
		perf_event_ctx_mark_detaching(ctx);
		ctx->handler = NULL;
	}
	pthread_cond_broadcast(&pb_ctx_list_cond);
	pthread_mutex_unlock(&pb_ctx_list_lock);

	if (atomic_load_explicit(&g_poll_thread_started, memory_order_acquire)) {
		pthread_join(g_poll_thread, NULL);
		atomic_store_explicit(&g_poll_thread_started, false, memory_order_release);
	}

	pthread_mutex_lock(&pb_ctx_list_lock);
	while (!list_empty(&pb_ctx_list)) {
		ctx = list_first_entry(&pb_ctx_list, struct perf_event_handler_ctx, list);
		list_del(&ctx->list);
		if (ctx->pb) {
			perf_buffer__free(ctx->pb);
			ctx->pb = NULL;
		}
		free(ctx);
	}
	while (!list_empty(&pb_ctx_ref_list)) {
		ref = list_first_entry(&pb_ctx_ref_list, struct perf_event_epoll_ref, list);
		list_del(&ref->list);
		free(ref);
	}
	pthread_mutex_unlock(&pb_ctx_list_lock);

	atomic_store_explicit(&g_lost_events, 0, memory_order_relaxed);
}

static void __handle_perf_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct perf_event_handler_ctx *pb_ctx = ctx;

	if (atomic_load_explicit(&g_stop, memory_order_acquire) || atomic_load_explicit(&pb_ctx->detaching, memory_order_acquire) || !pb_ctx->handler) {
		return;
	}

	pb_ctx->handler(data, data_sz, NULL);
}

static void __handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	atomic_fetch_add_explicit(&g_lost_events, lost_cnt, memory_order_relaxed);
	BPF_WARN("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int bpf_event_poll_register(int perf_map_fd, int page_cnt, bpf_event_process_fn fn)
{
	int epoll_fd = -1;
	struct perf_event_handler_ctx *ctx = NULL;
	struct perf_event_epoll_ref *ref = NULL;
	struct epoll_event event;

	epoll_fd = atomic_load_explicit(&g_epoll_fd, memory_order_acquire);
	if (atomic_load_explicit(&g_stop, memory_order_acquire) || epoll_fd == -1 || !atomic_load_explicit(&g_poll_thread_started, memory_order_acquire) || !fn) {
		BPF_ERR("bpf_event_poll not init\n");
		return -1;
	}

	ctx = calloc(1, sizeof(struct perf_event_handler_ctx));
	if (!ctx) {
		BPF_ERR("failed to alloc ctx errno=%d\n", errno);
		return -1;
	}

	ref = calloc(1, sizeof(struct perf_event_epoll_ref));
	if (!ref) {
		BPF_ERR("failed to alloc epoll ref errno=%d\n", errno);
		free(ctx);
		return -1;
	}

	ctx->handler = fn;
	ctx->perf_map_fd = perf_map_fd;
	ctx->ref = ref;

	ctx->pb = perf_buffer__new(ctx->perf_map_fd, page_cnt, __handle_perf_event, __handle_lost_events, ctx, NULL);
	if (!ctx->pb) {
		BPF_ERR("failed to alloc perf_buffer errno=%d\n", errno);
		free(ref);
		free(ctx);
		return -1;
	}
	atomic_init(&ctx->detaching, false);
	atomic_init(&ctx->active_consumers, 0);
	atomic_init(&ref->ctx, ctx);

	pthread_mutex_lock(&pb_ctx_list_lock);
	list_add(&ctx->list, &pb_ctx_list);
	list_add(&ref->list, &pb_ctx_ref_list);
	pthread_mutex_unlock(&pb_ctx_list_lock);

	event.events = EPOLLIN;
	event.data.ptr = ref;

	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, perf_buffer__epoll_fd(ctx->pb), &event) < 0) {
		BPF_ERR("failed to add perf buffer fd to epoll errno=%d\n", errno);
		pthread_mutex_lock(&pb_ctx_list_lock);
		list_del(&ctx->list);
		list_del(&ref->list);
		pthread_mutex_unlock(&pb_ctx_list_lock);
		perf_buffer__free(ctx->pb);
		free(ref);
		free(ctx);
		return -1;
	}

	return 0;
}

void bpf_event_poll_detach_epoll(int perf_map_fd)
{
	int epoll_fd = -1;
	struct perf_event_handler_ctx *ctx = NULL;
	bool found = false;

	epoll_fd = atomic_load_explicit(&g_epoll_fd, memory_order_acquire);
	if (epoll_fd == -1 || !atomic_load_explicit(&g_poll_thread_started, memory_order_acquire))
		return;

	pthread_mutex_lock(&pb_ctx_list_lock);

	list_for_each_entry(ctx, &pb_ctx_list, list)
	{
		if (ctx->perf_map_fd == perf_map_fd) {
			found = true;
			break;
		}
	}

	if (found)
		epoll_ctl(epoll_fd, EPOLL_CTL_DEL, perf_buffer__epoll_fd(ctx->pb), NULL);

	pthread_mutex_unlock(&pb_ctx_list_lock);

	return;
}

void bpf_event_poll_unregister_buf(int perf_map_fd)
{
	struct perf_event_handler_ctx *ctx = NULL;
	bool found = false;

	pthread_mutex_lock(&pb_ctx_list_lock);

	list_for_each_entry(ctx, &pb_ctx_list, list)
	{
		if (ctx->perf_map_fd == perf_map_fd) {
			found = true;
			break;
		}
	}

	if (found) {
		perf_event_ctx_mark_detaching(ctx);
		list_del(&ctx->list);
		/*
		 * Poll thread callbacks can still hold ctx after epoll detach.
		 * Wait for active consumers before freeing perf_buffer and ctx.
		 */
		while (atomic_load_explicit(&ctx->active_consumers, memory_order_acquire)) {
			pthread_cond_wait(&pb_ctx_list_cond, &pb_ctx_list_lock);
		}

		perf_buffer__free(ctx->pb);
		ctx->pb = NULL;
		ctx->handler = NULL;
		free(ctx);
	}

	pthread_cond_broadcast(&pb_ctx_list_cond);
	pthread_mutex_unlock(&pb_ctx_list_lock);

	return;
}

void bpf_event_poll_get_stats(struct bpf_event_poll_stats *stats)
{
	if (!stats)
		return;

	stats->lost_events = atomic_load_explicit(&g_lost_events, memory_order_relaxed);
}
