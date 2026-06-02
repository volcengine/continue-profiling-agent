// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include <cpa_bpf/perf_stack_capture.h>

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <linux/perf_event.h>

#ifndef hweight64
#define hweight64(w) __builtin_popcountll(w)
#endif

#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <syscall.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <asm/perf_regs.h>
#include <sys/epoll.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <linux/ring_buffer.h>

#include "core.h"

struct perf_stack_capture_ctx {
	int mmap_page_cnt;
	size_t mmap_size;
	int perf_cpu_num;
	perf_event_handler_fn handler;
	void *handler_data;
	int *pmu_fds;
	void **mmap_bufs;
	atomic_bool stop_thread;
	pthread_t poll_thread;
	int epoll_fd;
	struct epoll_event *epoll_events;
	int sleep_us;
	atomic_ullong lost_events;
};

static void hexdump_u64(const void *ptr, size_t size)
{
	const unsigned char *u8_ptr = (const unsigned char *)ptr;
	size_t i, j;

	for (i = 0; i < size; i += 16) {
		BPF_INFOE("%p:  ", u8_ptr + i);

		if (i + 8 <= size)
			fprintf(stderr, "%016lx ", *(unsigned long *)(u8_ptr + i));
		else
			fprintf(stderr, "%-17s", "");

		if (i + 16 <= size)
			fprintf(stderr, "%016lx", *(unsigned long *)(u8_ptr + i + 8));
		else
			fprintf(stderr, "%-16s", "");

		fprintf(stderr, "   ");
		for (j = 0; j < 16; j++) {
			if (i + j < size) {
				unsigned char c = u8_ptr[i + j];
				if (c >= 32 && c <= 126)
					fprintf(stderr, "%c", c);
				else
					fprintf(stderr, ".");
			}
		}
		fprintf(stderr, "\n");
	}
}

static unsigned long sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_REGS_USER | PERF_SAMPLE_STACK_USER;

struct perf_stack_event global_sample;

static unsigned long event_count = 1;
static __attribute__((unused)) void print_perf_stack_event(struct perf_stack_event *event)
{
	BPF_INFOE("[%10lu]: TID pid=%u, tid=%u, cpu=%u, time=%lu\n", event_count++, event->pid, event->tid, event->cpu, event->time);
	BPF_INFOE("print: REGS_USER rsp=0x%lx, rip=0x%lx\n", event->rsp, event->rip);

	BPF_INFOE("print: CALLCHAIN kstack_sz=%lu\n", event->kstack_sz);
	hexdump_u64(event->kstack, 64);
	BPF_INFOE("print: CALLCHAIN ustack_sz=%lu\n", event->ustack_sz);
	hexdump_u64(event->ustack, 64);

	BPF_INFOE("print: STACK_USER ustack_raw_sz=%lu\n", event->ustack_raw_sz);
	hexdump_u64(event->ustack_raw, event->ustack_raw_sz >= 32 ? 32 : event->ustack_raw_sz);
}

#define READ_U32(dst)                                                                                                                                                                                                                                          \
	do {                                                                                                                                                                                                                                                   \
		if (remaining < sizeof(unsigned int))                                                                                                                                                                                                          \
			goto out;                                                                                                                                                                                                                              \
		memcpy(&(dst), ptr, sizeof(unsigned int));                                                                                                                                                                                                     \
		ptr += sizeof(unsigned int);                                                                                                                                                                                                                   \
		remaining -= sizeof(unsigned int);                                                                                                                                                                                                             \
	} while (0)
#define READ_U64(dst)                                                                                                                                                                                                                                          \
	do {                                                                                                                                                                                                                                                   \
		if (remaining < sizeof(unsigned long))                                                                                                                                                                                                         \
			goto out;                                                                                                                                                                                                                              \
		memcpy(&(dst), ptr, sizeof(unsigned long));                                                                                                                                                                                                    \
		ptr += sizeof(unsigned long);                                                                                                                                                                                                                  \
		remaining -= sizeof(unsigned long);                                                                                                                                                                                                            \
	} while (0)

#define KERNEL_STACK_START (0xffffffffffffff80)
#define USER_STACK_START (0xfffffffffffffe00)

static void parse_perf_stack_event(void *data, unsigned long type, struct perf_stack_event *out, size_t data_size)
{
	unsigned char *ptr = data;
	size_t remaining = data_size;
	unsigned long nr = 0;

	memset(out, 0, sizeof(*out));
	if (!data || data_size == 0)
		goto out;

	if (type & PERF_SAMPLE_TID) {
		READ_U32(out->pid);
		READ_U32(out->tid);
	}

	if (type & PERF_SAMPLE_TIME)
		READ_U64(out->time);

	if (type & PERF_SAMPLE_CPU) {
		READ_U32(out->cpu);
		// reserved field
		if (remaining < sizeof(unsigned int))
			goto out;
		ptr += sizeof(unsigned int);
		remaining -= sizeof(unsigned int);
	}

	if (type & PERF_SAMPLE_CALLCHAIN) {
		READ_U64(nr);

		out->kstack_sz = 0;
		out->ustack_sz = 0;

		enum {
			SEARCHING,
			IN_KSTACK,
			IN_USTACK,
		} state = SEARCHING;

		if (nr > remaining / sizeof(unsigned long))
			nr = remaining / sizeof(unsigned long);

		for (unsigned long i = 0; i < nr; i++) {
			unsigned long ip = 0;
			READ_U64(ip);

			if (ip == KERNEL_STACK_START) {
				state = IN_KSTACK;
			} else if (ip == USER_STACK_START) {
				state = IN_USTACK;
			} else if (state == IN_KSTACK && out->kstack_sz < MAX_STACK_DEPTH) {
				out->kstack[out->kstack_sz++] = ip;
			} else if (state == IN_USTACK && out->ustack_sz < MAX_STACK_DEPTH) {
				out->ustack[out->ustack_sz++] = ip;
			}
		}
	}

	if (type & PERF_SAMPLE_REGS_USER) {
		unsigned long abi = 0;
		READ_U64(abi);
		if (abi != PERF_SAMPLE_REGS_ABI_NONE) {
			if (abi == PERF_SAMPLE_REGS_ABI_64) {
				READ_U64(out->rbp);
#if defined(__CPA_BPF_ARCH_arm64)
				READ_U64(out->lr);
#endif
				READ_U64(out->rsp);
				READ_U64(out->rip);
			} else if (abi == PERF_SAMPLE_REGS_ABI_32) {
				READ_U32(out->rbp);
#if defined(__CPA_BPF_ARCH_arm64)
				READ_U64(out->lr);
#endif
				READ_U32(out->rsp);
				READ_U32(out->rip);
			} else {
				goto out;
			}
		}
	}

	if (type & PERF_SAMPLE_STACK_USER) {
		READ_U64(out->ustack_raw_sz);
		if (!out->ustack_raw_sz) {
			goto out;
		}

		unsigned long raw_size = out->ustack_raw_sz;
		if (raw_size > remaining) {
			goto out;
		}
		if (remaining < raw_size + sizeof(unsigned long))
			goto out;

		const unsigned char *raw = ptr;
		ptr += raw_size;
		remaining -= raw_size;

		unsigned long dyn_size = 0;
		READ_U64(dyn_size);
		if (dyn_size > sizeof(out->ustack_raw))
			dyn_size = sizeof(out->ustack_raw);

		size_t copy_size = raw_size;
		if (copy_size > MAX_USER_STACK_DUMP_SIZE)
			copy_size = MAX_USER_STACK_DUMP_SIZE;
		if (copy_size > dyn_size)
			copy_size = dyn_size;

		size_t offset = out->rsp % 4096;
		size_t copy_limit = sizeof(out->ustack_raw) - offset;
		if (copy_size > copy_limit)
			copy_size = copy_limit;

		if (copy_size) {
			memcpy(out->ustack_raw + offset, raw, copy_size);
			out->ustack_raw_sz = copy_size + offset;
		} else {
			out->ustack_raw_sz = offset;
		}
	}

	// print_perf_stack_event(out);
out:

	return;
}

static char copy_buf[64 * 1024 + 4 * 1024];

static void process_perf_data(struct perf_stack_capture_ctx *ctx, int cpu)
{
	struct perf_event_mmap_page *header = ctx->mmap_bufs[cpu];
	unsigned long data_tail;
	unsigned long data_head;
	long page_sz = sysconf(_SC_PAGESIZE);
	void *base = (char *)header + page_sz;

	for (;;) {
		data_head = ring_buffer_read_head(header);
		data_tail = header->data_tail;

		if (data_head == data_tail)
			break;

		bool error = false;

		while (data_tail < data_head) {
			struct perf_event_header *event_header = base + (data_tail % ctx->mmap_size);

			if ((void *)event_header + event_header->size > base + ctx->mmap_size) {
				void *copy_start = event_header;
				size_t len_first = base + ctx->mmap_size - copy_start;
				size_t len_second = event_header->size - len_first;

				memcpy(copy_buf, copy_start, len_first);
				memcpy(copy_buf + len_first, base, len_second);
				event_header = (struct perf_event_header *)copy_buf;
			}

			if (event_header->type == PERF_RECORD_SAMPLE) {
				size_t payload_size = 0;
				if (event_header->size > sizeof(struct perf_event_header))
					payload_size = event_header->size - sizeof(struct perf_event_header);
				parse_perf_stack_event((void *)((unsigned char *)event_header + sizeof(struct perf_event_header)), sample_type, &global_sample, payload_size);
				if (ctx->handler)
					ctx->handler(&global_sample, ctx->handler_data);
			} else if (event_header->type == PERF_RECORD_LOST) {
				struct {
					uint64_t id;
					uint64_t lost_events;
				} lost_record = { 0 };
				size_t payload_size = 0;

				if (event_header->size > sizeof(struct perf_event_header))
					payload_size = event_header->size - sizeof(struct perf_event_header);

				if (payload_size >= sizeof(lost_record)) {
					memcpy(&lost_record, (unsigned char *)event_header + sizeof(struct perf_event_header), sizeof(lost_record));
					atomic_fetch_add_explicit(&ctx->lost_events, lost_record.lost_events, memory_order_relaxed);
				}
			}

			data_tail += event_header->size;
		}

		ring_buffer_write_tail(header, data_tail);

		if (error)
			break;
	}
}

static void *poll_event_thread(void *arg)
{
	struct perf_stack_capture_ctx *ctx = arg;
	int i;

	while (!atomic_load(&ctx->stop_thread)) {
		usleep(ctx->sleep_us);
		for (i = 0; i < ctx->perf_cpu_num; i++)
			process_perf_data(ctx, i);
	}
	return NULL;
}

struct perf_stack_capture_ctx *perf_setup_stack_capture_event(int sample_period, perf_event_handler_fn handler, void *handler_data)
{
	struct perf_stack_capture_ctx *ctx;
	int cpu;
	const int page_cnt = PERF_STACK_CAPTURE_PAGE_CNT;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->perf_cpu_num = get_nprocs();
	ctx->mmap_page_cnt = page_cnt;
	ctx->mmap_size = ctx->mmap_page_cnt * sysconf(_SC_PAGESIZE);
	ctx->handler = handler;
	ctx->handler_data = handler_data;

	ctx->sleep_us = 1000 * 1000 / sample_period;
	atomic_init(&ctx->lost_events, 0);

	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.size = sizeof(struct perf_event_attr),
		.config = PERF_COUNT_SW_CPU_CLOCK,
		.sample_freq = sample_period,
		.freq = 1,
		.sample_type = sample_type,
		.sample_stack_user = MAX_USER_STACK_DUMP_SIZE,
#if defined(__CPA_BPF_ARCH_arm64)
		.sample_regs_user = ((1UL << PERF_REG_ARM64_SP) | (1UL << PERF_REG_ARM64_PC) | (1UL << PERF_REG_ARM64_X29) | (1UL << PERF_REG_ARM64_LR)),
#else
		.sample_regs_user = ((1UL << PERF_REG_X86_SP) | (1UL << PERF_REG_X86_IP) | (1UL << PERF_REG_X86_BP)),
#endif
		.disabled = 1,
		.exclude_kernel = 0,
		.exclude_user = 0,
		.exclude_hv = 0,
		.exclude_idle = 1,
	};

	ctx->pmu_fds = calloc(ctx->perf_cpu_num, sizeof(int));
	if (!ctx->pmu_fds) {
		BPF_ERR("failed to alloc pmu_fds\n");
		goto error;
	}
	ctx->mmap_bufs = calloc(ctx->perf_cpu_num, sizeof(void *));
	if (!ctx->mmap_bufs) {
		BPF_ERR("failed to alloc mmap_bufs\n");
		goto error;
	}

	ctx->epoll_events = calloc(ctx->perf_cpu_num, sizeof(struct epoll_event));
	if (!ctx->epoll_events) {
		BPF_ERR("failed to alloc epoll_events\n");
		goto error;
	}

	ctx->epoll_fd = -1;
	ctx->epoll_fd = epoll_create1(0);
	if (ctx->epoll_fd < 0) {
		BPF_ERR("failed to create epoll fd: %s\n", strerror(errno));
		goto error;
	}

	for (cpu = 0; cpu < ctx->perf_cpu_num; cpu++)
		ctx->pmu_fds[cpu] = -1;

	for (cpu = 0; cpu < ctx->perf_cpu_num; cpu++) {
		ctx->pmu_fds[cpu] = syscall(__NR_perf_event_open, &attr, -1, cpu, -1, 0);
		if (ctx->pmu_fds[cpu] < 0) {
			BPF_ERR("failed to open perf event cpu=%d sample_type=%lx: %s\n", cpu, sample_type, strerror(errno));
			goto error;
		}

		ctx->mmap_bufs[cpu] = mmap(NULL, ctx->mmap_size + sysconf(_SC_PAGESIZE), PROT_READ | PROT_WRITE, MAP_SHARED, ctx->pmu_fds[cpu], 0);
		if (ctx->mmap_bufs[cpu] <= 0) {
			BPF_ERR("failed to mmap perf buffer cpu=%d: %s\n", cpu, strerror(errno));
			ctx->mmap_bufs[cpu] = NULL;
			goto error;
		}

		struct epoll_event ev;
		ev.events = EPOLLIN;
		ev.data.u32 = cpu;
		if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, ctx->pmu_fds[cpu], &ev) < 0) {
			BPF_ERR("failed to add perf fd to epoll cpu=%d: %s\n", cpu, strerror(errno));
			goto error;
		}
	}

	atomic_init(&ctx->stop_thread, false);

	if (pthread_create(&ctx->poll_thread, NULL, poll_event_thread, ctx)) {
		BPF_ERR("failed to create poll thread\n");
		goto error;
	}

	for (cpu = 0; cpu < ctx->perf_cpu_num; cpu++) {
		if (ctx->pmu_fds[cpu] >= 0) {
			if (ioctl(ctx->pmu_fds[cpu], PERF_EVENT_IOC_RESET, 0) < 0) {
				BPF_ERR("failed to enable perf event cpu=%d: %s\n", cpu, strerror(errno));
				goto error;
			}
			if (ioctl(ctx->pmu_fds[cpu], PERF_EVENT_IOC_ENABLE, 0) < 0) {
				BPF_ERR("failed to enable perf event cpu=%d: %s\n", cpu, strerror(errno));
				goto error;
			}
		}
	}

	return ctx;
error:
	perf_stack_capture_cleanup(ctx);
	return NULL;
}

void perf_stack_capture_cleanup(struct perf_stack_capture_ctx *ctx)
{
	int i;

	if (!ctx)
		return;

	atomic_store(&ctx->stop_thread, true);
	if (ctx->poll_thread)
		pthread_join(ctx->poll_thread, NULL);

	if (ctx->epoll_fd >= 0)
		close(ctx->epoll_fd);

	if (ctx->epoll_events)
		free(ctx->epoll_events);

	if (ctx->pmu_fds) {
		for (i = 0; i < ctx->perf_cpu_num; i++) {
			if (ctx->pmu_fds[i] >= 0)
				close(ctx->pmu_fds[i]);
		}
		free(ctx->pmu_fds);
	}
	if (ctx->mmap_bufs) {
		for (i = 0; i < ctx->perf_cpu_num; i++) {
			if (ctx->mmap_bufs[i])
				munmap(ctx->mmap_bufs[i], ctx->mmap_size + sysconf(_SC_PAGESIZE));
		}
		free(ctx->mmap_bufs);
	}
	free(ctx);
}

void perf_stack_capture_get_stats(struct perf_stack_capture_ctx *ctx, struct perf_stack_capture_stats *stats)
{
	if (!stats)
		return;

	stats->lost_events = 0;
	if (!ctx)
		return;

	stats->lost_events = atomic_load_explicit(&ctx->lost_events, memory_order_relaxed);
}
