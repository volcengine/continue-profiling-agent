// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include <stack_capture.skel.h>
#include <stack_capture_ringbuf.skel.h>
#include <linux/perf_event.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
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
static struct stack_capture_ringbuf_bpf *rb_obj;
static struct bpf_object *sc_obj;
static bool use_ringbuf;
/* 0 = auto, 1 = force perfbuf, 2 = force ringbuf. */
static int datapath_requested;
static unsigned int ring_size_bytes = 16U * 1024U * 1024U;

void stack_capture_set_datapath(int mode, unsigned int ring_mb)
{
	datapath_requested = mode;
	if (ring_mb)
		ring_size_bytes = ring_mb * 1024U * 1024U;
}

static struct bpf_program *sc_prog(const char *name)
{
	return bpf_object__find_program_by_name(sc_obj, name);
}

static int sc_map_fd(const char *name)
{
	return bpf_map__fd(bpf_object__find_map_by_name(sc_obj, name));
}
static int perf_output_events, percpu_config, stack_content_buf;
static int kernel_event_buf;
static int comm_stack_limit_fd = -1;
static pthread_mutex_t comm_stack_limit_lock = PTHREAD_MUTEX_INITIALIZER;
static struct stack_capture_comm_key *comm_stack_limit_keys = NULL;
static unsigned int comm_stack_limit_key_count = 0;
struct stack_capture_config *percpu_config_buf = NULL;

char *cpu_array_buf = NULL;

static struct bpf_link **links = NULL;
static struct bpf_link *probe_links = NULL;
static struct bpf_link *coredump_link = NULL;
static bool coredump_capture_enabled = false;

void stack_capture_set_coredump_capture(bool enabled)
{
	coredump_capture_enabled = enabled;
}

/* Shared BPF runtime handles and buffers. */
static int stack_capture_size = 8192;

static bool ringbuf_map_supported(void)
{
return libbpf_probe_bpf_map_type(BPF_MAP_TYPE_RINGBUF, NULL) > 0;
}

static void sc_preload_resize(struct bpf_object *bo, bool ring)
{
	bpf_map__set_max_entries(
		bpf_object__find_map_by_name(bo, "stack_content_buf"),
		libbpf_num_possible_cpus());
	bpf_map__set_max_entries(
		bpf_object__find_map_by_name(bo, "kernel_event_buf"),
		libbpf_num_possible_cpus());
	if (ring)
		bpf_map__set_max_entries(
			bpf_object__find_map_by_name(bo, "events_rb"),
			ring_size_bytes);
}

static int init_bpf_module(const struct bpf_object_open_opts *optsp)
{
	bool try_ringbuf = datapath_requested == 2 ||
			   (datapath_requested == 0 && ringbuf_map_supported());

	if (try_ringbuf) {
		rb_obj = stack_capture_ringbuf_bpf__open_opts(optsp);
		if (!rb_obj) {
			if (datapath_requested == 2) {
				BPF_ERR("ringbuf bpf open failed func=%s\n", __func__);
				return -1;
			}
			BPF_INFO("ringbuf open failed, falling back to perf buffer\n");
		} else {
			sc_preload_resize(rb_obj->obj, true);
			if (!coredump_capture_enabled)
				bpf_program__set_autoload(
					rb_obj->progs.stack_capture_coredump, false);
			int ret = stack_capture_ringbuf_bpf__load(rb_obj);
			if (ret) {
				stack_capture_ringbuf_bpf__destroy(rb_obj);
				rb_obj = NULL;
				if (datapath_requested == 2) {
					BPF_ERR("ringbuf bpf load failed ret=%d\n", ret);
					return ret;
				}
				BPF_INFO("ringbuf load failed ret=%d, falling back\n", ret);
			} else {
				use_ringbuf = true;
			}
		}
	}

	if (!use_ringbuf) {
		obj = stack_capture_bpf__open_opts(optsp);
		if (!obj) {
			BPF_ERR("bpf open failed func=%s\n", __func__);
			return -1;
		}
		sc_preload_resize(obj->obj, false);
		if (!coredump_capture_enabled)
			bpf_program__set_autoload(obj->progs.stack_capture_coredump, false);
		int ret = stack_capture_bpf__load(obj);
		if (ret) {
			BPF_ERR("bpf load failed func=%s\n", __func__);
			return ret;
		}
	}

	sc_obj = use_ringbuf ? rb_obj->obj : obj->obj;

	links = (struct bpf_link **)calloc(libbpf_num_possible_cpus(), sizeof(struct bpf_link *));
	if (!links) {
		BPF_ERR("failed to alloc buffer\n");
		return -1;
	}

	stack_content_buf = sc_map_fd("stack_content_buf");
	kernel_event_buf = sc_map_fd("kernel_event_buf");
	comm_stack_limit_fd = sc_map_fd("comm_stack_limit");
	percpu_config = sc_map_fd("percpu_config");
	perf_output_events = use_ringbuf ? sc_map_fd("events_rb")
				       : sc_map_fd("perf_output_events");
	BPF_INFO("stack_capture datapath=%s ring_size=%u\n",
		 use_ringbuf ? "ringbuf" : "perfbuf",
		 use_ringbuf ? ring_size_bytes : 0);
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

	(void)stack_capture_clear_comm_stack_limits();
	free(comm_stack_limit_keys);
	comm_stack_limit_keys = NULL;
	comm_stack_limit_key_count = 0;
	comm_stack_limit_fd = -1;

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

	if (use_ringbuf) {
bpf_event_poll_unregister_no_free(perf_output_events);
stack_capture_ringbuf_bpf__destroy(rb_obj);
rb_obj = NULL;
} else {
bpf_event_poll_unregister(perf_output_events, stack_capture_bpf__destroy(obj));
}
sc_obj = NULL;
use_ringbuf = false;


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

static struct bpf_link *attach_by_name(const char *probe_type)
{
	char *probe_spec = NULL;
	char *probe_type_name = NULL;
	char *probe_target = NULL;
	char *probe_subtype = NULL;
	char *saveptr = NULL;
	struct bpf_link *link = NULL;

	if (!probe_type) {
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
		link = bpf_program__attach_kprobe(sc_prog("stack_capture_kprobe"), false, probe_target);
	} else if (strcmp(probe_type_name, "kretprobe") == 0) {
		if (!probe_target)
			goto err;
		link = bpf_program__attach_kprobe(sc_prog("stack_capture_kprobe"), true, probe_target);
	} else if (strcmp(probe_type_name, "tracepoint") == 0) {
		if (!probe_target || !probe_subtype)
			goto err;
		link = bpf_program__attach_tracepoint(sc_prog("stack_capture_tp"), probe_target, probe_subtype);
	} else {
		errno = ENOTSUP;
		goto err;
	}

err:
	free(probe_spec);
	return link;
}

#define USER_CAPTURE_PAGE_CNT 512
/*
 * Kernel-only events carry the fixed stack_event header (~2 KiB of
 * kernel stack); two pages only buffer two or three samples per CPU at
 * 99 Hz, so use four to avoid overwrite drops in kernel-only mode.
 */
#define KERNEL_CAPTURE_PAGE_CNT 4

static int stack_capture_build_comm_key(const char *comm,
				  struct stack_capture_comm_key *key)
{
	size_t len;

	if (!comm || !key)
		return -EINVAL;

	len = strnlen(comm, sizeof(key->comm));
	if (len == 0)
		return -EINVAL;

	memset(key, 0, sizeof(*key));
	memcpy(key->comm, comm, len);
	return 0;
}

static int stack_capture_find_comm_key_locked(const struct stack_capture_comm_key *key)
{
	for (unsigned int i = 0; i < comm_stack_limit_key_count; i++)
		if (memcmp(&comm_stack_limit_keys[i], key, sizeof(*key)) == 0)
			return (int)i;
	return -1;
}

int stack_capture_set_comm_stack_limit(const char *comm, unsigned int stack_size)
{
	struct stack_capture_comm_key key;
	bool is_new = false;
	int err;

	if (!obj || comm_stack_limit_fd < 0)
		return -ENOENT;
	if (stack_size != 0 &&
	    (stack_size < 4096 || stack_size > MAX_STACK_EVENT_USER_STACK_SIZE ||
		     stack_size % 4096 != 0))
		return -EINVAL;

	err = stack_capture_build_comm_key(comm, &key);
	if (err)
		return err;

	pthread_mutex_lock(&comm_stack_limit_lock);
	if (stack_capture_find_comm_key_locked(&key) < 0) {
		struct stack_capture_comm_key *grown = NULL;

		if (comm_stack_limit_key_count >= STACK_CAPTURE_COMM_LIMIT_MAX_ENTRIES) {
			err = -ENOSPC;
			goto out;
		}
		grown = realloc(comm_stack_limit_keys,
			       (comm_stack_limit_key_count + 1) * sizeof(*grown));
		if (!grown) {
			err = -ENOMEM;
			goto out;
		}
		comm_stack_limit_keys = grown;
		comm_stack_limit_keys[comm_stack_limit_key_count++] = key;
		is_new = true;
	}
	if (bpf_map_update_elem(comm_stack_limit_fd, &key, &stack_size, BPF_ANY) != 0) {
		err = -errno;
		if (is_new)
			comm_stack_limit_key_count--;
		goto out;
	}
	err = 0;
out:
	pthread_mutex_unlock(&comm_stack_limit_lock);
	return err;
}

int stack_capture_clear_comm_stack_limits(void)
{
	int err = 0;

	pthread_mutex_lock(&comm_stack_limit_lock);
	if (obj && comm_stack_limit_fd >= 0) {
		for (unsigned int i = 0; i < comm_stack_limit_key_count; i++) {
			if (bpf_map_delete_elem(comm_stack_limit_fd,
						&comm_stack_limit_keys[i]) != 0 &&
			    errno != ENOENT && err == 0)
				err = -errno;
		}
	}
	comm_stack_limit_key_count = 0;
	pthread_mutex_unlock(&comm_stack_limit_lock);
	return err;
}

int stack_capture_get_comm_stack_limit_stat(struct stack_capture_comm_limit_stat *stat)
{
	if (!stat)
		return -EINVAL;

	memset(stat, 0, sizeof(*stat));
	stat->capacity = STACK_CAPTURE_COMM_LIMIT_MAX_ENTRIES;
	pthread_mutex_lock(&comm_stack_limit_lock);
	stat->entries = comm_stack_limit_key_count;
	pthread_mutex_unlock(&comm_stack_limit_lock);
	return 0;
}

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
	int poll_ret = use_ringbuf ?
bpf_event_poll_register_ringbuf(perf_output_events, fn) :
bpf_event_poll_register(perf_output_events, page_cnt, fn);
if (poll_ret < 0) {
		BPF_ERR("failed to register\n");
		err = -1;
		goto clear;
	}

	/*
	 * Kernel-only mode uses the fixed-size per-CPU event buffer; user
	 * stack mode needs the full payload-sized scratch buffer.
	 */
	int array_buf_size = user_ctx->only_kernel ? (int)sizeof(struct stack_event) : STACK_EVENT_MAX_PAYLOAD;
	int content_map_fd = user_ctx->only_kernel ? kernel_event_buf : stack_content_buf;

	cpu_array_buf = calloc(libbpf_num_possible_cpus(), array_buf_size);
	if (!cpu_array_buf) {
		BPF_ERR("failed to alloc cpu_array_buf\n");
		err = -ENOMEM;
		goto clear;
	}
	memset(cpu_array_buf, 0, array_buf_size * libbpf_num_possible_cpus());
	char *cpu_array_buf_ptr = cpu_array_buf;

	for (i = 0; i < libbpf_num_possible_cpus(); i++) {
		bpf_map_update_elem(content_map_fd, &i, cpu_array_buf_ptr, 0);
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
	config.bpf_exec_time_guard_ns = user_ctx->bpf_exec_time_guard_ns;

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
		probe_links = attach_by_name(user_ctx->probe_name);
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
		links[i] = bpf_program__attach_perf_event(sc_prog("stack_capture_timer"), fd);
		if (!links[i]) {
			BPF_ERR("failed to attach perf event cpu=%d errno=%d\n", i, errno);
			close(fd);
			err = -errno;
			if (!err)
				err = -EIO;
			goto clear;
		}
	}

	if (coredump_capture_enabled) {
		coredump_link = bpf_program__attach_kprobe(
			sc_prog("stack_capture_coredump"), false, "do_coredump");
		if (!coredump_link) {
			BPF_ERR("failed to attach kprobe/do_coredump errno=%d\n", errno);
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
