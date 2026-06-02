// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CPA_BPF_BPF_EVENT_POLL_H
#define CPA_BPF_BPF_EVENT_POLL_H

#include <bpf/libbpf.h>
#include <cpa_bpf/bpf_event.h>
#include <stdint.h>

/**
 * Register event polling thread and handlers.
 */
int bpf_event_poll_init(void);

/**
 * Destroy event polling thread and release internals.
 */
void bpf_event_poll_destroy(void);

/**
 * Register callback for a perf-map file descriptor.
 */
int bpf_event_poll_register(int perf_map_fd, int page_cnt, bpf_event_process_fn fn);

/**
 * struct bpf_event_poll_stats - shared perf-buffer transport counters
 * @lost_events: lost records reported by libbpf perf-buffer callbacks
 */
struct bpf_event_poll_stats {
	uint64_t lost_events;
};

/**
 * bpf_event_poll_get_stats - snapshot perf-buffer transport counters
 * @stats: destination statistics object
 */
void bpf_event_poll_get_stats(struct bpf_event_poll_stats *stats);

/* Internal helper only: prefer bpf_event_poll_unregister(). */
void bpf_event_poll_detach_epoll(int perf_map_fd);
/* Internal helper only: prefer bpf_event_poll_unregister(). */
void bpf_event_poll_unregister_buf(int perf_map_fd);

/**
 * Unregister polling events by a perf map.
 *
 * @param perf_map_fd The file descriptor of the perf map used for output in the BPF program.
 * @param free_obj destruction expression for module context.
 */
#define bpf_event_poll_unregister(__perf_map_fd, free_obj)                                                                                                                                                                                                     \
	{                                                                                                                                                                                                                                                      \
		bpf_event_poll_detach_epoll(__perf_map_fd);                                                                                                                                                                                                    \
		bpf_event_poll_unregister_buf(__perf_map_fd);                                                                                                                                                                                                  \
		free_obj;                                                                                                                                                                                                                                      \
	}

#define bpf_event_poll_unregister_no_free(__perf_map_fd)                                                                                                                                                                                                       \
	{                                                                                                                                                                                                                                                      \
		bpf_event_poll_detach_epoll(__perf_map_fd);                                                                                                                                                                                                    \
		bpf_event_poll_unregister_buf(__perf_map_fd);                                                                                                                                                                                                  \
	}
#endif
