// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include <offcpu_capture.skel.h>
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
#include "offcpu_capture.h"

/**
 * @file offcpu_capture.c
 * @brief off-CPU capture backend setup and finish_task_switch attachment.
 */

static struct offcpu_capture_bpf *obj;
static int perf_output_events, percpu_config, stack_content_buf, pid_start;
static struct offcpu_capture_config *percpu_config_buf = NULL;

static char *cpu_array_buf = NULL;

static struct bpf_link *links = NULL;

static int offcpu_capture_size = 8192;
static char *probe_func = NULL;

/**
 * Open skeleton, set per-cpu map size, and resolve map fds.
 */
static int init_bpf_module(const struct bpf_object_open_opts *optsp)
{
	int ret;

	obj = offcpu_capture_bpf__open_opts(optsp);
	if (!obj) {
		BPF_ERR("bpf open failed func=%s\n", __func__);
		return -1;
	}

	bpf_map__set_max_entries(bpf_object__find_map_by_name(obj->obj, "stack_content_buf"), libbpf_num_possible_cpus());

	ret = offcpu_capture_bpf__load(obj);
	if (ret) {
		BPF_ERR("bpf load failed func=%s\n", __func__);
		return ret;
	}

	stack_content_buf = bpf_map__fd(obj->maps.stack_content_buf);
	perf_output_events = bpf_map__fd(obj->maps.perf_output_events);
	percpu_config = bpf_map__fd(obj->maps.percpu_config);
	pid_start = bpf_map__fd(obj->maps.pid_start);

	return 0;
}

static void exit_bpf_module(void)
{
	if (!obj)
		return;

	if (links) {
		bpf_link__destroy(links);
		links = NULL;
	}

	if (cpu_array_buf)
		free(cpu_array_buf);
	if (percpu_config_buf)
		free(percpu_config_buf);
	if (probe_func) {
		free(probe_func);
		probe_func = NULL;
	}

	bpf_event_poll_unregister(perf_output_events, offcpu_capture_bpf__destroy(obj));

	obj = NULL;
}

BPF_MODULE(offcpu_capture, "4.14");

/**
 * Populate offcpu capture configuration from user context.
 */
static int setup_offcpu_capture_config(struct offcpu_capture_config *config, int pid, char *comm)
{
	config->irqoff_threshold = 0;
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
	 * Keep stack address math identical to on-CPU capture: stack_offset
	 * finds pt_regs, task_max rejects non-user stack pointers.
	 */
	config->task_max = get_task_size_max();
	config->offcpu_capture_size = offcpu_capture_size;

	config->pid = pid;
	snprintf(config->comm, sizeof(config->comm), "%s", comm);
	config->comm_len = strnlen(config->comm, sizeof(config->comm));

	return 0;
}

int set_offcpu_capture_size(int size)
{
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

	offcpu_capture_size = size;

	return 0;
}

/**
 * Allocate shared buffers and attach to finish_task_switch kprobe.
 */
int setup_offcpu_capture_event(int freq, bpf_event_process_fn fn, struct offcpu_capture_ctx *user_ctx)
{
	uint32_t zero = 0;
	int i = 0, err = 0;

	if (!user_ctx || !fn) {
		err = -EINVAL;
		goto clear;
	}

	if (bpf_event_poll_register(perf_output_events, 4096, fn) < 0) {
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

	percpu_config_buf = (struct offcpu_capture_config *)calloc(libbpf_num_possible_cpus(), sizeof(struct offcpu_capture_config));
	if (!percpu_config_buf) {
		BPF_ERR("failed to alloc percpu_config_buf\n");
		err = -ENOMEM;
		goto clear;
	}

	struct offcpu_capture_config config;

	if (setup_offcpu_capture_config(&config, user_ctx->pid, user_ctx->comm)) {
		BPF_ERR("failed to setup offcpu_capture_config\n");
		err = -EINVAL;
		goto clear;
	}

	for (i = 0; i < libbpf_num_possible_cpus(); i++)
		memcpy(&percpu_config_buf[i], &config, sizeof(struct offcpu_capture_config));

	err = bpf_map_update_elem(percpu_config, &zero, percpu_config_buf, 0);
	if (err) {
		BPF_ERR("failed to update percpu_config_buf errno=%d\n", errno);
		if (err > 0)
			err = -err;
		else if (!err)
			err = -EIO;
		goto clear;
	}

	probe_func = find_kprobe_functions("finish_task_switch");
	if (!probe_func) {
		BPF_ERR("failed to find kprobe function finish_task_switch\n");
		err = -ENOENT;
		goto clear;
	}

	links = bpf_program__attach_kprobe(obj->progs.finish_task_switch_k, false, probe_func);
	if (!links) {
		BPF_ERR("failed to attach kprobe function finish_task_switch\n");
		err = -ENOENT;
		goto clear;
	}

	return 0;

clear:
	bpf_event_poll_unregister_no_free(perf_output_events);

	if (links) {
		bpf_link__destroy(links);
		links = NULL;
	}
	free(cpu_array_buf);
	cpu_array_buf = NULL;
	free(percpu_config_buf);
	percpu_config_buf = NULL;
	if (probe_func) {
		free(probe_func);
		probe_func = NULL;
	}

	if (!err)
		err = -EINVAL;

	return err;
}
