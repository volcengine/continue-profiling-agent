// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include <stack_capture.skel.h>
#include <stack_capture_ringbuf.skel.h>
#include <stack_capture_lite.skel.h>
#include <stack_capture_pagefault.skel.h>
#include <linux/perf_event.h>
#include <pthread.h>
#include <stdio.h>
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
#include <cpa_bpf/capabilities.h>
#include "bpf_event_poll.h"
#include "target_ctl.h"
#include "stack_capture.h"

/**
 * @file stack_capture.c
 * @brief eBPF stack capture backend setup and attachment.
 */

static struct stack_capture_bpf *obj;
static struct stack_capture_ringbuf_bpf *rb_obj;
static struct stack_capture_lite_bpf *lite_obj;
/*
 * --pagefault: the only object loaded; a judge on the new anonymous page
 * hook tail-calls its capture program instead of perf timers firing it.
 */
static struct stack_capture_pagefault_bpf *pf_obj;
static struct bpf_object *sc_obj;
static bool use_ringbuf;
static bool use_lite;
static bool pf_requested;
static struct stack_capture_pagefault_cfg pf_request;
static int pf_events = -1;
#define PF_LINKS_MAX 16
static struct bpf_link *pf_links[PF_LINKS_MAX];
/* 0 = auto, 1 = force perfbuf, 2 = force ringbuf. */
static int datapath_requested;
static unsigned int ring_size_bytes = 16U * 1024U * 1024U;

void stack_capture_set_pagefault(const struct stack_capture_pagefault_cfg *cfg)
{
	pf_requested = cfg && cfg->enabled;
	if (pf_requested)
		pf_request = *cfg;
}

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
static int stacks_fd = -1;

/* Dynamic target selection (see target_ctl.h). */
static int target_owner_fd = -1;
static bool target_dynamic_requested;
static int target_pids_fd = -1;
static int t0_prog_fd = -1;

void stack_capture_set_target(int owner_fd, bool dynamic)
{
	target_owner_fd = owner_fd;
	target_dynamic_requested = dynamic;
}

int stack_capture_target_pids_fd(void)
{
	return target_pids_fd;
}

int stack_capture_t0_prog_fd(void)
{
	return t0_prog_fd;
}

/*
 * Between open and load of every object: adopt target_ctl's target_pids, or
 * shrink the unused private copy, and load the t0 program only when a
 * dynamic selection can tail-call it.
 */
static void prepare_target(struct bpf_map *pids_map, struct bpf_program *t0)
{
	int err;

	bpf_program__set_autoload(t0, target_dynamic_requested);
	if (!target_dynamic_requested) {
		target_ctl_adopt_pids_map(pids_map, -1);
		return;
	}
	if (target_owner_fd < 0 || target_ctl_force_private_map())
		return;
	err = target_ctl_adopt_pids_map(pids_map, target_owner_fd);
	if (err)
		BPF_WARN("stack_capture: target_pids not shared (%d)\n", err);
}

/* On 4.14 a reused map has no name: reach it through the skeleton. */
static void record_target_fds(struct bpf_map *pids_map, struct bpf_program *t0)
{
	target_pids_fd = bpf_map__fd(pids_map);
	t0_prog_fd = target_dynamic_requested ? bpf_program__fd(t0) : -1;
}
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
static struct bpf_link *exit_link = NULL;
static bool exit_capture_enabled = false;
/* exit capture's own selection; none means the global one */
static unsigned long long exit_comms[STACK_CAPTURE_EXIT_MAX_COMMS][2];
static int n_exit_comms;
static unsigned int exit_pids[STACK_CAPTURE_EXIT_MAX_PIDS];
static int n_exit_pids;

void stack_capture_set_coredump_capture(bool enabled)
{
	coredump_capture_enabled = enabled;
}

/* The one switch: it decides both the autoload and the attach. */
void stack_capture_set_exit_capture(bool enabled)
{
	exit_capture_enabled = enabled;
}

int stack_capture_set_exit_targets(const char *const *comms, int n_comms, const unsigned int *pids, int n_pids)
{
	if (n_comms < 0 || n_comms > STACK_CAPTURE_EXIT_MAX_COMMS || n_pids < 0 ||
	    n_pids > STACK_CAPTURE_EXIT_MAX_PIDS)
		return -EINVAL;
	memset(exit_comms, 0, sizeof(exit_comms));
	for (int i = 0; i < n_comms; i++) {
		size_t len = strlen(comms[i]);

		if (!len || len >= TASK_COMM_LEN)
			return -EINVAL;
		/* zero-padded like the kernel's comm read into 16 bytes */
		memcpy(exit_comms[i], comms[i], len);
	}
	n_exit_comms = n_comms;
	for (int i = 0; i < n_pids; i++)
		exit_pids[i] = pids[i];
	n_exit_pids = n_pids;
	return 0;
}

/* Sidecar kprobes attached by hand, released on every teardown path. */
static void detach_sidecar_links(void)
{
	if (coredump_link) {
		bpf_link__destroy(coredump_link);
		coredump_link = NULL;
	}
	if (exit_link) {
		bpf_link__destroy(exit_link);
		exit_link = NULL;
	}
}

/* Shared BPF runtime handles and buffers. */
static int stack_capture_size = 8192;

static bool ringbuf_map_supported(void)
{
	return cpa_capability_supported(cpa_capabilities_get(), CPA_CAP_RINGBUF);
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

/* The full objects call bpf_get_stack from all three program types. */
static bool get_stack_supported(void)
{
	const struct cpa_capability_set *caps = cpa_capabilities_get();

	return cpa_capability_supported(caps, CPA_CAP_GET_STACK_PERF_EVENT) &&
	       cpa_capability_supported(caps, CPA_CAP_GET_STACK_KPROBE) &&
	       cpa_capability_supported(caps, CPA_CAP_GET_STACK_TRACEPOINT);
}

static int load_ringbuf(const struct bpf_object_open_opts *optsp)
{
	int ret;

	rb_obj = stack_capture_ringbuf_bpf__open_opts(optsp);
	if (!rb_obj)
		return -1;
	sc_preload_resize(rb_obj->obj, true);
	if (!coredump_capture_enabled)
		bpf_program__set_autoload(rb_obj->progs.stack_capture_coredump, false);
	if (!exit_capture_enabled)
		bpf_program__set_autoload(rb_obj->progs.stack_capture_exit_group, false);
	prepare_target(rb_obj->maps.target_pids, rb_obj->progs.stack_capture_t0);
	ret = stack_capture_ringbuf_bpf__load(rb_obj);
	if (ret) {
		stack_capture_ringbuf_bpf__destroy(rb_obj);
		rb_obj = NULL;
		return ret;
	}
	sc_obj = rb_obj->obj;
	use_ringbuf = true;
	return 0;
}

static int load_perfbuf(const struct bpf_object_open_opts *optsp)
{
	int ret;

	obj = stack_capture_bpf__open_opts(optsp);
	if (!obj)
		return -1;
	sc_preload_resize(obj->obj, false);
	if (!coredump_capture_enabled)
		bpf_program__set_autoload(obj->progs.stack_capture_coredump, false);
	if (!exit_capture_enabled)
		bpf_program__set_autoload(obj->progs.stack_capture_exit_group, false);
	prepare_target(obj->maps.target_pids, obj->progs.stack_capture_t0);
	ret = stack_capture_bpf__load(obj);
	if (ret) {
		stack_capture_bpf__destroy(obj);
		obj = NULL;
		return ret;
	}
	sc_obj = obj->obj;
	return 0;
}

static int load_lite(const struct bpf_object_open_opts *optsp)
{
	int ret;

	lite_obj = stack_capture_lite_bpf__open_opts(optsp);
	if (!lite_obj)
		return -1;
	sc_preload_resize(lite_obj->obj, false);
	if (!coredump_capture_enabled)
		bpf_program__set_autoload(lite_obj->progs.stack_capture_coredump, false);
	if (!exit_capture_enabled)
		bpf_program__set_autoload(lite_obj->progs.stack_capture_exit_group, false);
	prepare_target(lite_obj->maps.target_pids, lite_obj->progs.stack_capture_t0);
	ret = stack_capture_lite_bpf__load(lite_obj);
	if (ret) {
		stack_capture_lite_bpf__destroy(lite_obj);
		lite_obj = NULL;
		return ret;
	}
	sc_obj = lite_obj->obj;
	use_lite = true;
	return 0;
}

static int load_pagefault(const struct bpf_object_open_opts *optsp)
{
	bool folio = cpa_pagefault_rmap()->entry == CPA_PF_ENTRY_FOLIO;
	int ret;

	pf_obj = stack_capture_pagefault_bpf__open_opts(optsp);
	if (!pf_obj)
		return -1;
	sc_preload_resize(pf_obj->obj, false);
	/* Only the judge, its capture program and the release hooks run. */
	bpf_program__set_autoload(pf_obj->progs.stack_capture_timer, false);
	bpf_program__set_autoload(pf_obj->progs.stack_capture_tp, false);
	bpf_program__set_autoload(pf_obj->progs.stack_capture_kprobe, false);
	bpf_program__set_autoload(pf_obj->progs.stack_capture_coredump, false);
	bpf_program__set_autoload(pf_obj->progs.stack_capture_exit_group, false);
	/*
	 * One entry for new pages, the one the kernel has: the folio entry
	 * reads struct folio, which older kernels lack.  A kernel without one
	 * loads the page entry and is refused at the attach.
	 */
	bpf_program__set_autoload(pf_obj->progs.pf_new_anon_page, !folio);
	bpf_program__set_autoload(pf_obj->progs.pf_new_anon_folio, folio);
	prepare_target(pf_obj->maps.target_pids, pf_obj->progs.stack_capture_t0);
	/* a t0 CPU sample has no place in a profile of bytes */
	bpf_program__set_autoload(pf_obj->progs.stack_capture_t0, false);
	ret = stack_capture_pagefault_bpf__load(pf_obj);
	if (ret) {
		stack_capture_pagefault_bpf__destroy(pf_obj);
		pf_obj = NULL;
		return ret;
	}
	sc_obj = pf_obj->obj;
	return 0;
}

/*
 * Three objects, best first: ringbuf (5.8+), perfbuf, and lite for kernels
 * without bpf_get_stack or bounded loops (before 5.3, e.g. 4.14): kernel
 * stacks by stack id, a 16 KiB user-stack window and no frame-pointer user
 * stack.  A kernel without bpf_get_stack goes to lite directly; otherwise
 * lite is the last resort when the perfbuf object does not load.
 */
static int init_bpf_module(const struct bpf_object_open_opts *optsp)
{
	bool has_get_stack = get_stack_supported();
	bool try_ringbuf = datapath_requested == 2 ||
			   (datapath_requested == 0 && has_get_stack &&
			    ringbuf_map_supported());
	int ret = -1;

	if (pf_requested) {
		ret = load_pagefault(optsp);
		if (ret) {
			BPF_ERR("pagefault bpf load failed ret=%d\n", ret);
			return ret;
		}
	}

	if (!sc_obj && try_ringbuf) {
		ret = load_ringbuf(optsp);
		if (ret && datapath_requested == 2) {
			BPF_ERR("ringbuf bpf load failed ret=%d\n", ret);
			return ret;
		}
		if (ret)
			BPF_INFO("ringbuf load failed ret=%d, falling back to perf buffer\n", ret);
	}

	if (!sc_obj && has_get_stack) {
		ret = load_perfbuf(optsp);
		if (ret)
			BPF_WARN("bpf load failed ret=%d, trying the lite object\n", ret);
	}

	if (!sc_obj) {
		ret = load_lite(optsp);
		if (ret) {
			BPF_ERR("bpf load failed func=%s ret=%d\n", __func__, ret);
			return ret;
		}
		/* a downgrade: say what is lost */
		BPF_WARN("stack_capture: %s, using the lite object: kernel stacks by stack id, "
			 "user stack copy limited to 16 KiB, no frame-pointer user stack\n",
			 has_get_stack ? "the full object did not load" : "no bpf_get_stack");
	}

	links = (struct bpf_link **)calloc(libbpf_num_possible_cpus(), sizeof(struct bpf_link *));
	if (!links) {
		BPF_ERR("failed to alloc buffer\n");
		return -1;
	}

	stack_content_buf = sc_map_fd("stack_content_buf");
	kernel_event_buf = sc_map_fd("kernel_event_buf");
	comm_stack_limit_fd = sc_map_fd("comm_stack_limit");
	percpu_config = sc_map_fd("percpu_config");
	stacks_fd = use_lite ? sc_map_fd("stacks") : -1;
	if (use_ringbuf)
		record_target_fds(rb_obj->maps.target_pids, rb_obj->progs.stack_capture_t0);
	else if (pf_obj)
		record_target_fds(pf_obj->maps.target_pids, pf_obj->progs.stack_capture_t0);
	else if (use_lite)
		record_target_fds(lite_obj->maps.target_pids, lite_obj->progs.stack_capture_t0);
	else
		record_target_fds(obj->maps.target_pids, obj->progs.stack_capture_t0);
	if (pf_obj) {
		t0_prog_fd = -1;
		pf_events = sc_map_fd("pf_events");
	}
	perf_output_events = use_ringbuf ? sc_map_fd("events_rb")
				       : sc_map_fd("perf_output_events");
	BPF_INFO("stack_capture object=%s datapath=%s ring_size=%u\n",
		 pf_obj ? "pagefault" : use_lite ? "lite" : "full",
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
	if (!sc_obj)
		return;

	detach_sidecar_links();
	for (i = 0; i < PF_LINKS_MAX; i++) {
		if (pf_links[i])
			bpf_link__destroy(pf_links[i]);
		pf_links[i] = NULL;
	}
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
	} else if (pf_obj) {
		bpf_event_poll_unregister_no_free(pf_events);
		bpf_event_poll_unregister(perf_output_events, stack_capture_pagefault_bpf__destroy(pf_obj));
		pf_obj = NULL;
		pf_events = -1;
	} else if (use_lite) {
		bpf_event_poll_unregister(perf_output_events, stack_capture_lite_bpf__destroy(lite_obj));
		lite_obj = NULL;
	} else {
		bpf_event_poll_unregister(perf_output_events, stack_capture_bpf__destroy(obj));
		obj = NULL;
	}
	sc_obj = NULL;
	use_ringbuf = false;
	use_lite = false;
	stacks_fd = -1;
	target_pids_fd = -1;
	t0_prog_fd = -1;
}

/*
 * A lite object's samples carry a stack id instead of the kernel stack;
 * copy the stack out of its map.  Returns the number of entries, 0 if the
 * id does not resolve.  Entries are never deleted: with
 * BPF_F_REUSE_STACKID the map is a fixed table where a new stack replaces
 * the one in its bucket, so it never fills; a sample still queued when its
 * bucket is replaced gets the newer stack (accepted on these kernels).
 */
int stack_capture_lookup_kstack(long kstack_id, unsigned long *kstack, int max_level)
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

/* Pages of the release event buffer: small records, bursts of munmap. */
#define PF_EVENTS_PAGE_CNT 16

/*
 * Attach the pagefault judge, the address-space hooks and the release
 * syscalls.  Everything must attach: a profile missing a release path would
 * silently overstate memory.
 */
static int attach_pagefault(const struct stack_capture_ctx *user_ctx)
{
	const struct cpa_pagefault_rmap *rmap = cpa_pagefault_rmap();
	bool folio = rmap->entry == CPA_PF_ENTRY_FOLIO;
	const char *syms[] = { rmap->symbol, "setup_new_exec", "exit_mmap" };
	struct bpf_program *progs[] = {
		folio ? pf_obj->progs.pf_new_anon_folio : pf_obj->progs.pf_new_anon_page,
		pf_obj->progs.pf_exec,
		pf_obj->progs.pf_mm_gone,
		pf_obj->progs.pf_munmap_enter,
		pf_obj->progs.pf_munmap_exit,
		pf_obj->progs.pf_madvise_enter,
		pf_obj->progs.pf_madvise_exit,
		pf_obj->progs.pf_brk_enter,
		pf_obj->progs.pf_brk_exit,
		pf_obj->progs.pf_mmap_enter,
		pf_obj->progs.pf_mmap_exit,
		pf_obj->progs.pf_mremap_enter,
		pf_obj->progs.pf_mremap_exit,
	};
	struct pf_config cfg = {
		.salt = pf_request.salt,
		.tgid = user_ctx->target_dynamic ? 0 : (uint32_t)user_ctx->pid,
		.sample_mask = pf_request.sample_pages - 1,
	};
	unsigned long addrs[2] = { 0 };
	uint32_t zero = 0;
	int prog_fd;

	_Static_assert(sizeof(progs) / sizeof(progs[0]) <= PF_LINKS_MAX, "pf_links too small");
	if (rmap->entry == CPA_PF_ENTRY_NONE) {
		if (rmap->error)
			BPF_ERR("pagefault: %s (error %d)\n", rmap->why, rmap->error);
		else
			BPF_ERR("pagefault: %s\n", rmap->why);
		return -ENOTSUP;
	}
	/* by name: with kptr_restrict=2 every address reads 0 */
	if (find_ksyms_addr(syms + 1, addrs, 2) != 2) {
		BPF_ERR("pagefault: setup_new_exec or exit_mmap is not available on this kernel\n");
		return -ENOTSUP;
	}
	if ((!user_ctx->target_dynamic && user_ctx->pid <= 0) || !pf_request.sample_pages ||
	    (pf_request.sample_pages & (pf_request.sample_pages - 1)))
		return -EINVAL;

	if (bpf_map_update_elem(bpf_map__fd(pf_obj->maps.pf_cfg), &zero, &cfg, BPF_ANY))
		return -errno;
	prog_fd = bpf_program__fd(pf_obj->progs.stack_capture_pf);
	if (bpf_map_update_elem(bpf_map__fd(pf_obj->maps.pf_progs), &zero, &prog_fd, BPF_ANY))
		return -errno;
	/* the kernel's own count of dropped records, beside BPF's */
	if (bpf_event_poll_register_lost(pf_events, PF_EVENTS_PAGE_CNT, pf_request.release_fn,
					 pf_request.events_lost_fn) < 0)
		return -EIO;

	for (unsigned int i = 0; i < sizeof(progs) / sizeof(progs[0]); i++) {
		pf_links[i] = bpf_program__attach(progs[i]);
		if (!pf_links[i]) {
			BPF_ERR("pagefault: attaching %s failed: %d\n", bpf_program__name(progs[i]), -errno);
			return -ENOTSUP;
		}
	}
	/* what the session runs on, always logged */
	fprintf(stderr, "pagefault: new anonymous pages from %s\n", rmap->symbol);
	if (rmap->unverified)
		BPF_WARN("pagefault: %s\n", rmap->unverified);
	if (cfg.tgid)
		fprintf(stderr, "pagefault: pid=%u sample_pages=%u hooks attached\n", cfg.tgid, pf_request.sample_pages);
	else
		fprintf(stderr, "pagefault: target_ctl selection sample_pages=%u hooks attached\n",
			pf_request.sample_pages);
	return 0;
}

int stack_capture_pagefault_state(struct pf_state *out)
{
	uint32_t zero = 0;

	if (!pf_obj || bpf_map_lookup_elem(bpf_map__fd(pf_obj->maps.pf_state), &zero, out))
		return -ENOENT;
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
bpf_event_poll_register_lost(perf_output_events, page_cnt, fn,
			     pf_obj ? pf_request.stack_lost_fn : NULL);
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

	struct stack_capture_config config = { 0 };
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
	config.target_dynamic = user_ctx->target_dynamic;
	config.exit_own_targets = n_exit_comms || n_exit_pids;
	config.n_exit_comms = n_exit_comms;
	memcpy(config.exit_comms, exit_comms, sizeof(config.exit_comms));
	config.n_exit_pids = n_exit_pids;
	memcpy(config.exit_pids, exit_pids, sizeof(config.exit_pids));

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

	if (pf_obj) {
		err = attach_pagefault(user_ctx);
		if (err)
			goto clear;
		return 0;
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

	if (exit_capture_enabled) {
		exit_link = bpf_program__attach_kprobe(
			sc_prog("stack_capture_exit_group"), false, "do_group_exit");
		if (!exit_link) {
			BPF_ERR("failed to attach kprobe/do_group_exit errno=%d\n", errno);
			err = -errno;
			if (!err)
				err = -EIO;
			goto clear;
		}
	}

	return 0;

clear:
	bpf_event_poll_unregister_no_free(perf_output_events);
	if (pf_obj)
		bpf_event_poll_unregister_no_free(pf_events);
	detach_sidecar_links();
	for (i = 0; i < PF_LINKS_MAX; i++) {
		if (pf_links[i])
			bpf_link__destroy(pf_links[i]);
		pf_links[i] = NULL;
	}

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
