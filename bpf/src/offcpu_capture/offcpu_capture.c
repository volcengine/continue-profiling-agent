// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include <offcpu_capture.skel.h>
#include <offcpu_capture_lite.skel.h>
#include <string.h>
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
#include "target_ctl.h"

/**
 * @file offcpu_capture.c
 * @brief off-CPU capture backend setup and finish_task_switch attachment.
 */

static struct offcpu_capture_bpf *obj;
static struct offcpu_capture_lite_bpf *lite_obj;
static struct bpf_object *oc_obj;
static struct bpf_program *finish_task_switch_prog;
static int perf_output_events, percpu_config, stack_content_buf, pid_start;
static int stacks_fd = -1;

/* Dynamic target selection (see target_ctl.h). */
static int target_owner_fd = -1;
static bool target_dynamic_requested;
static int target_pids_fd = -1;

void offcpu_capture_set_target(int owner_fd, bool dynamic)
{
	target_owner_fd = owner_fd;
	target_dynamic_requested = dynamic;
}

int offcpu_capture_target_pids_fd(void)
{
	return target_pids_fd;
}

/* Between open and load: share target_ctl's map, or shrink the private one. */
static void prepare_target(struct bpf_map *pids_map)
{
	int err;

	if (!target_dynamic_requested) {
		target_ctl_adopt_pids_map(pids_map, -1);
		return;
	}
	if (target_owner_fd < 0 || target_ctl_force_private_map())
		return;
	err = target_ctl_adopt_pids_map(pids_map, target_owner_fd);
	if (err)
		BPF_WARN("offcpu_capture: target_pids not shared (%d)\n", err);
}
static struct offcpu_capture_config *percpu_config_buf = NULL;

static char *cpu_array_buf = NULL;

static struct bpf_link *links = NULL;

static int offcpu_capture_size = 8192;
static char *probe_func = NULL;

static int oc_map_fd(const char *name)
{
	return bpf_map__fd(bpf_object__find_map_by_name(oc_obj, name));
}

/*
 * Open, size and load the full object, or the lite one on kernels without
 * bpf_get_stack or bounded loops (before 5.3, e.g. 4.14): kernel stacks by
 * stack id, a 16 KiB user-stack window, no frame-pointer user stack.
 */
static int init_bpf_module(const struct bpf_object_open_opts *optsp)
{
	bool has_get_stack = libbpf_probe_bpf_helper(BPF_PROG_TYPE_KPROBE,
						     BPF_FUNC_get_stack, NULL) > 0;
	int ret = -1;

	if (has_get_stack) {
		obj = offcpu_capture_bpf__open_opts(optsp);
		if (obj) {
			bpf_map__set_max_entries(obj->maps.stack_content_buf, libbpf_num_possible_cpus());
			prepare_target(obj->maps.target_pids);
			ret = offcpu_capture_bpf__load(obj);
			if (ret) {
				offcpu_capture_bpf__destroy(obj);
				obj = NULL;
				BPF_WARN("bpf load failed ret=%d, trying the lite object\n", ret);
			} else {
				oc_obj = obj->obj;
				finish_task_switch_prog = obj->progs.finish_task_switch_k;
			}
		}
	}

	if (!oc_obj) {
		lite_obj = offcpu_capture_lite_bpf__open_opts(optsp);
		if (!lite_obj) {
			BPF_ERR("bpf open failed func=%s\n", __func__);
			return -1;
		}
		bpf_map__set_max_entries(lite_obj->maps.stack_content_buf, libbpf_num_possible_cpus());
		prepare_target(lite_obj->maps.target_pids);
		ret = offcpu_capture_lite_bpf__load(lite_obj);
		if (ret) {
			BPF_ERR("bpf load failed func=%s ret=%d\n", __func__, ret);
			offcpu_capture_lite_bpf__destroy(lite_obj);
			lite_obj = NULL;
			return ret;
		}
		oc_obj = lite_obj->obj;
		finish_task_switch_prog = lite_obj->progs.finish_task_switch_k;
		stacks_fd = oc_map_fd("stacks");
		/* a downgrade: say what is lost */
		BPF_WARN("offcpu_capture: %s, using the lite object: kernel stacks by stack id, "
			 "user stack copy limited to 16 KiB, no frame-pointer user stack\n",
			 has_get_stack ? "the full object did not load" : "no bpf_get_stack");
	}

	/* on 4.14 a reused map has no name: reach it through the skeleton */
	target_pids_fd = bpf_map__fd(lite_obj ? lite_obj->maps.target_pids : obj->maps.target_pids);
	stack_content_buf = oc_map_fd("stack_content_buf");
	perf_output_events = oc_map_fd("perf_output_events");
	percpu_config = oc_map_fd("percpu_config");
	pid_start = oc_map_fd("pid_start");
	BPF_INFO("offcpu_capture object=%s\n", lite_obj ? "lite" : "full");
	return 0;
}

static void exit_bpf_module(void)
{
	if (!oc_obj)
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

	if (lite_obj) {
		bpf_event_poll_unregister(perf_output_events, offcpu_capture_lite_bpf__destroy(lite_obj));
		lite_obj = NULL;
	} else {
		bpf_event_poll_unregister(perf_output_events, offcpu_capture_bpf__destroy(obj));
		obj = NULL;
	}
	oc_obj = NULL;
	finish_task_switch_prog = NULL;
	stacks_fd = -1;
	target_pids_fd = -1;
}

/* See stack_capture_lookup_kstack(). */
int offcpu_capture_lookup_kstack(long kstack_id, unsigned long *kstack, int max_level)
{
	unsigned long ips[MAX_KERNEL_STACK_LEVEL] = { 0 };
	__u32 key = (__u32)kstack_id;
	int n = 0;

	if (stacks_fd < 0 || kstack_id < 0 || !kstack || max_level <= 0)
		return 0;
	if (bpf_map_lookup_elem(stacks_fd, &key, ips))
		return 0;
	while (n < max_level && n < MAX_KERNEL_STACK_LEVEL && ips[n])
		n++;
	memcpy(kstack, ips, n * sizeof(ips[0]));
	return n;
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
	config.target_dynamic = user_ctx->target_dynamic;

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

	links = bpf_program__attach_kprobe(finish_task_switch_prog, false, probe_func);
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
