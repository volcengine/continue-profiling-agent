// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include <stack_capture.skel.h>
#include <linux/perf_event.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <stdint.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <cpa_bpf.h>
#include "core.h"
#include "trace_helpers.h"
#include <cpa_bpf/bpf_event.h>
#include "bpf_event_poll.h"
#include "stack_capture.h"

/**
 * @file stack_capture.c
 * @brief eBPF stack capture backend setup and attachment.
 */

static struct stack_capture_bpf *obj;
static int perf_output_events, percpu_config, stack_content_buf;
struct stack_capture_config *percpu_config_buf = NULL;

char *cpu_array_buf = NULL;

static struct bpf_link **links = NULL;
static struct bpf_link *probe_links = NULL;

/* Shared BPF runtime handles and buffers. */
static int stack_capture_size = 8192;

static int init_bpf_module(const struct bpf_object_open_opts *optsp)
{
	int ret;

	obj = stack_capture_bpf__open_opts(optsp);
	if (!obj) {
		BPF_ERR("bpf open failed func=%s\n", __func__);
		return -1;
	}

	bpf_map__set_max_entries(bpf_object__find_map_by_name(obj->obj, "stack_content_buf"), libbpf_num_possible_cpus());

	ret = stack_capture_bpf__load(obj);
	if (ret) {
		BPF_ERR("bpf load failed func=%s\n", __func__);
		return ret;
	}

	links = (struct bpf_link **)calloc(libbpf_num_possible_cpus(), sizeof(struct bpf_link *));
	if (!links) {
		BPF_ERR("failed to alloc buffer\n");
		return -1;
	}

	stack_content_buf = bpf_map__fd(obj->maps.stack_content_buf);
	perf_output_events = bpf_map__fd(obj->maps.perf_output_events);
	percpu_config = bpf_map__fd(obj->maps.percpu_config);
	return 0;
}

/**
 * Release all perf links and polling buffers for stack capture.
 */
static void exit_bpf_module(void)
{
	int i = 0;
	if (!obj)
		return;

	if (links) {
		for (i = 0; i < libbpf_num_possible_cpus(); i++) {
			if (!links[i])
				continue;
			bpf_link__destroy(links[i]);
		}
		free(links);
		links = NULL;
	}

	if (cpu_array_buf)
		free(cpu_array_buf);
	if (percpu_config_buf)
		free(percpu_config_buf);

	bpf_event_poll_unregister(perf_output_events, stack_capture_bpf__destroy(obj));

	obj = NULL;
}

BPF_MODULE(stack_capture, "4.14");

/**
 * Populate per-CPU configuration before attaching capture programs.
 */
static int setup_stack_capture_config(struct stack_capture_config *config, uint64_t irqoff_threshold)
{
	config->irqoff_threshold = irqoff_threshold / 1000;
	config->page_size = sysconf(_SC_PAGESIZE);
	if (config->page_size % 4096 != 0) {
		BPF_ERR("failed to get page size page_size=%u\n", config->page_size);
		return -1;
	}

#if defined(__CPA_BPF_ARCH_arm64)
	uint64_t min_thread_shift = 14 + (kernel_config_enabled("CONFIG_KASAN") ? 1 : 0);
	uint64_t min_thread_size = 1UL << min_thread_shift;
	if (config->page_size > min_thread_size)
		config->stack_offset = config->page_size;
	else
		config->stack_offset = min_thread_size;
#elif defined(__CPA_BPF_ARCH_x86)
	config->stack_offset = config->page_size << (kernel_config_enabled("CONFIG_KASAN") ? 3 : 2);
#endif

	/*
	 * stack_offset locates pt_regs at the task stack tail. task_max bounds
	 * user SP validation before BPF copies raw user-stack pages.
	 */
	config->task_max = get_task_size_max();
	config->stack_capture_size = stack_capture_size;
	BPF_INFO("stack_capture config page_size=0x%x stack_offset=0x%x task_max=0x%lx capture_size=0x%x\n", config->page_size, config->stack_offset, config->task_max, config->stack_capture_size);

	return 0;
}

int set_stack_capture_size(int size)
{
	/*
	 * Capture size is page-aligned so BPF copies a bounded number of fixed
	 * 4KiB chunks and keeps verifier-visible bounds stable.
	 */
	if (size > MAX_STACK_EVENT_USER_STACK_SIZE) {
		BPF_ERR("stack capture size too large size=%d\n", size);
		return -1;
	}

	if (size < 4096) {
		BPF_ERR("stack capture size too small size=%d\n", size);
		return -1;
	}

	if (size % 4096 != 0) {
		BPF_ERR("stack capture size must align to 4096 size=%d\n", size);
		return -1;
	}

	stack_capture_size = size;

	return 0;
}

static struct bpf_link *attach_by_name(struct stack_capture_bpf *obj, const char *probe_type)
{
	char *probe_spec = NULL;
	char *probe_type_name = NULL;
	char *probe_target = NULL;
	char *probe_subtype = NULL;
	char *saveptr = NULL;
	struct bpf_link *link = NULL;

	if (!obj || !probe_type) {
		errno = EINVAL;
		return NULL;
	}

	probe_spec = strdup(probe_type);
	if (!probe_spec)
		return NULL;

	probe_type_name = strtok_r(probe_spec, ":", &saveptr);
	probe_target = strtok_r(NULL, ":", &saveptr);
	probe_subtype = strtok_r(NULL, ":", &saveptr);

	if (strcmp(probe_type_name, "kprobe") == 0) {
		if (!probe_target)
			goto err;
		link = bpf_program__attach_kprobe(obj->progs.stack_capture_kprobe, false, probe_target);
	} else if (strcmp(probe_type_name, "kretprobe") == 0) {
		if (!probe_target)
			goto err;
		link = bpf_program__attach_kprobe(obj->progs.stack_capture_kprobe, true, probe_target);
	} else if (strcmp(probe_type_name, "tracepoint") == 0) {
		if (!probe_target || !probe_subtype)
			goto err;
		link = bpf_program__attach_tracepoint(obj->progs.stack_capture_tp, probe_target, probe_subtype);
	} else {
		errno = ENOTSUP;
		goto err;
	}

err:
	free(probe_spec);
	return link;
}

#define USER_CAPTURE_PAGE_CNT 512
#define KERNEL_CAPTURE_PAGE_CNT 2

/**
 * Setup stack capture map/program and attach either explicit probe or CPU timers.
 */
int setup_stack_capture_event(int freq, bpf_event_process_fn fn, struct stack_capture_ctx *user_ctx)
{
	uint64_t threshold_ns = (uint64_t)(1000 * 1000 * 1000) / freq;

	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.freq = 0,
		.sample_period = threshold_ns,
		.config = PERF_COUNT_SW_CPU_CLOCK,
	};

	uint32_t zero = 0;
	int fd = 0, i = 0, err = 0, page_cnt = 0;

	if (!user_ctx || !fn) {
		err = -EINVAL;
		goto clear;
	}

	if (user_ctx->only_kernel)
		page_cnt = KERNEL_CAPTURE_PAGE_CNT;
	else
		page_cnt = USER_CAPTURE_PAGE_CNT;

	/*
	 * Kernel-only mode sends much smaller events, so use a smaller perf
	 * buffer to reduce idle memory while keeping user-stack mode roomy.
	 */
	if (bpf_event_poll_register(perf_output_events, page_cnt, fn) < 0) {
		BPF_ERR("failed to register\n");
		err = -1;
		goto clear;
	}

	int array_buf_size = STACK_EVENT_MAX_PAYLOAD;

	cpu_array_buf = calloc(libbpf_num_possible_cpus(), array_buf_size);
	if (!cpu_array_buf) {
		BPF_ERR("failed to alloc cpu_array_buf\n");
		err = -ENOMEM;
		goto clear;
	}
	memset(cpu_array_buf, 1, array_buf_size * libbpf_num_possible_cpus());
	char *cpu_array_buf_ptr = cpu_array_buf;

	for (i = 0; i < libbpf_num_possible_cpus(); i++) {
		bpf_map_update_elem(stack_content_buf, &i, cpu_array_buf_ptr, 0);
		cpu_array_buf_ptr += array_buf_size;
	}

	percpu_config_buf = (struct stack_capture_config *)calloc(libbpf_num_possible_cpus(), sizeof(struct stack_capture_config));
	if (!percpu_config_buf) {
		BPF_ERR("failed to alloc percpu_config_buf\n");
		err = -ENOMEM;
		goto clear;
	}

	struct stack_capture_config config;
	config.only_kernel = user_ctx->only_kernel;

	if (setup_stack_capture_config(&config, threshold_ns)) {
		BPF_ERR("failed to setup stack_capture_config\n");
		err = -EINVAL;
		goto clear;
	}

	const char *find_syms[] = { "__per_cpu_offset", "perf_throttled_count" };
	unsigned long addrs[2] = { 0 };

	int ret = find_ksyms_addr(find_syms, addrs, 2);
	if (ret != 2) {
		BPF_ERR("failed to find ksyms\n");
		err = -ENOENT;
		goto clear;
	}

	config.__per_cpu_offset_addr = addrs[0];
	config.perf_throttled_count_off = addrs[1];
	config.actual_perf_throttled_count_addr = 0;

	config.pid = user_ctx->pid;
	memset(config.comm, 0, sizeof(config.comm));
	if (user_ctx->comm)
		snprintf(config.comm, sizeof(config.comm), "%s", user_ctx->comm);
	config.comm_len = strnlen(config.comm, sizeof(config.comm));

	for (i = 0; i < libbpf_num_possible_cpus(); i++)
		memcpy(&percpu_config_buf[i], &config, sizeof(struct stack_capture_config));

	err = bpf_map_update_elem(percpu_config, &zero, percpu_config_buf, 0);
	if (err) {
		BPF_ERR("failed to update percpu_config_buf errno=%d\n", errno);
		if (!err)
			err = -EIO;
		else if (err > 0)
			err = -err;
		goto clear;
	}

	if (user_ctx->probe_name) {
		probe_links = attach_by_name(obj, user_ctx->probe_name);
		if (!probe_links) {
			BPF_ERR("failed to attach %s\n", user_ctx->probe_name);
			err = -ENOENT;
			goto clear;
		}
		return 0;
	}

	for (i = 0; i < libbpf_num_possible_cpus(); i++) {
		fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
		if (fd < 0) {
			if (errno == ENODEV)
				continue;
			BPF_ERR("failed to init perf sampling errno=%d\n", errno);
			err = -errno;
			goto clear;
		}
		links[i] = bpf_program__attach_perf_event(obj->progs.stack_capture_timer, fd);
		if (!links[i]) {
			BPF_ERR("failed to attach perf event cpu=%d errno=%d\n", i, errno);
			close(fd);
			err = -errno;
			if (!err)
				err = -EIO;
			goto clear;
		}
	}

	return 0;

clear:
	bpf_event_poll_unregister_no_free(perf_output_events);

	for (i = 0; i < libbpf_num_possible_cpus(); i++) {
		if (links && links[i]) {
			bpf_link__destroy(links[i]);
			links[i] = NULL;
		}
	}
	if (probe_links) {
		bpf_link__destroy(probe_links);
		probe_links = NULL;
	}

	free(cpu_array_buf);
	cpu_array_buf = NULL;
	free(percpu_config_buf);
	percpu_config_buf = NULL;

	if (!err)
		err = -EINVAL;

	return err;
}
