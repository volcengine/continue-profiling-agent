// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include <target_ctl.skel.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cpa_bpf.h>
#include "core.h"
#include "bpf_event_poll.h"
#include "target_ctl.h"

#define TARGET_CTL_PERF_PAGE_CNT 8

static struct target_ctl_bpf *obj;
static struct bpf_link *exec_link;
static struct bpf_link *fork_link;
static bool exec_via_tracepoint;
static int target_events_fd = -1;
static bool events_registered;

static int init_bpf_module(const struct bpf_object_open_opts *optsp)
{
	int ret;

	obj = target_ctl_bpf__open_opts(optsp);
	if (!obj) {
		BPF_ERR("bpf open failed func=%s\n", __func__);
		return -1;
	}

	ret = target_ctl_bpf__load(obj);
	if (ret) {
		BPF_ERR("bpf load failed func=%s ret=%d\n", __func__, ret);
		target_ctl_bpf__destroy(obj);
		obj = NULL;
		return ret;
	}

	target_events_fd = bpf_map__fd(obj->maps.target_events);
	return 0;
}

static void exit_bpf_module(void)
{
	if (exec_link) {
		bpf_link__destroy(exec_link);
		exec_link = NULL;
	}
	exec_via_tracepoint = false;
	if (fork_link) {
		bpf_link__destroy(fork_link);
		fork_link = NULL;
	}
	if (!obj)
		return;
	if (events_registered) {
		bpf_event_poll_unregister(target_events_fd,
					  target_ctl_bpf__destroy(obj));
		events_registered = false;
	} else {
		target_ctl_bpf__destroy(obj);
	}
	obj = NULL;
	target_events_fd = -1;
}

BPF_MODULE(target_ctl, "4.14");

/* Test switches that force the fallback paths. */
static bool env_flag(const char *name)
{
	const char *value = getenv(name);

	return value && value[0] && strcmp(value, "0") != 0;
}

int target_ctl_pids_fd(void)
{
	return obj ? bpf_map__fd(obj->maps.target_pids) : -1;
}

int target_ctl_latch_fd(void)
{
	return obj ? bpf_map__fd(obj->maps.target_latch) : -1;
}

int target_ctl_set_t0_prog(int prog_fd)
{
	__u32 zero = 0;

	if (!obj || prog_fd < 0)
		return -EINVAL;
	if (bpf_map_update_elem(bpf_map__fd(obj->maps.t0_progs), &zero,
				&prog_fd, BPF_ANY))
		return -errno;
	return 0;
}

int target_ctl_update_rules(const struct target_rules *rules)
{
	__u32 zero = 0;

	if (!obj || !rules)
		return -EINVAL;
	if (bpf_map_update_elem(bpf_map__fd(obj->maps.target_rules), &zero,
				rules, BPF_ANY))
		return -errno;
	return 0;
}

int target_ctl_start(const struct target_rules *rules, bpf_event_process_fn fn,
		     struct target_ctl_hooks *hooks)
{
	int ret;

	if (!obj || !rules || !hooks)
		return -EINVAL;

	ret = target_ctl_update_rules(rules);
	if (ret)
		return ret;

	if (fn && !events_registered) {
		if (bpf_event_poll_register(target_events_fd,
					    TARGET_CTL_PERF_PAGE_CNT, fn) < 0)
			return -EIO;
		events_registered = true;
	}

	if (!fork_link) {
		fork_link = bpf_program__attach(obj->progs.target_fork);
		if (!fork_link)
			BPF_WARN("target_ctl: attach wake_up_new_task failed: %d\n",
				 -errno);
	}
	/*
	 * 4.14 accepts one BPF program per tracepoint; when another tracer owns
	 * sched_process_exec, the kretprobe on setup_new_exec sees the same
	 * exec.  CPA_TARGET_FORCE_EXEC_KPROBE exercises that path.
	 */
	if (!exec_link && !env_flag("CPA_TARGET_FORCE_EXEC_KPROBE")) {
		exec_link = bpf_program__attach(obj->progs.target_exec);
		if (!exec_link)
			BPF_WARN("target_ctl: attach sched_process_exec failed: %d%s\n",
				 -errno, errno == EEXIST ?
				 " (tracepoint already owned by another BPF program)" : "");
		exec_via_tracepoint = exec_link != NULL;
	}
	if (!exec_link) {
		exec_link = bpf_program__attach(obj->progs.target_exec_kretprobe);
		if (!exec_link)
			BPF_WARN("target_ctl: attach setup_new_exec failed: %d\n",
				 -errno);
	}
	hooks->exec = exec_link != NULL;
	hooks->exec_tracepoint = exec_via_tracepoint;
	hooks->fork = fork_link != NULL;
	return 0;
}

int target_ctl_adopt_pids_map(struct bpf_map *consumer, int owner_fd)
{
	struct bpf_map_info info;
	__u32 len = sizeof(info);

	if (!consumer)
		return -EINVAL;

	if (owner_fd < 0)
		return bpf_map__set_max_entries(consumer, 1);

	memset(&info, 0, sizeof(info));
	if (bpf_obj_get_info_by_fd(owner_fd, &info, &len))
		return -errno;

	if (info.type != bpf_map__type(consumer) ||
	    info.key_size != bpf_map__key_size(consumer) ||
	    info.value_size != bpf_map__value_size(consumer) ||
	    info.max_entries != bpf_map__max_entries(consumer) ||
	    info.map_flags != bpf_map__map_flags(consumer)) {
		BPF_WARN("target_ctl: %s definition differs from owner "
			 "(type %u/%u key %u/%u value %u/%u entries %u/%u flags %#x/%#x); "
			 "keeping a private copy\n",
			 bpf_map__name(consumer), info.type, bpf_map__type(consumer),
			 info.key_size, bpf_map__key_size(consumer), info.value_size,
			 bpf_map__value_size(consumer), info.max_entries,
			 bpf_map__max_entries(consumer), info.map_flags,
			 bpf_map__map_flags(consumer));
		return -EXDEV;
	}

	/*
	 * On 4.14 struct bpf_map_info has no name, so libbpf renames the
	 * reused map to "".  Callers must reach it through the skeleton
	 * pointer, never through bpf_object__find_map_by_name().
	 */
	if (bpf_map__reuse_fd(consumer, owner_fd))
		return -errno;
	return 0;
}

uint32_t target_ctl_map_id(int fd)
{
	struct bpf_map_info info;
	__u32 len = sizeof(info);

	if (fd < 0)
		return 0;
	memset(&info, 0, sizeof(info));
	if (bpf_obj_get_info_by_fd(fd, &info, &len))
		return 0;
	return info.id;
}

bool target_ctl_force_private_map(void)
{
	return env_flag("CPA_TARGET_FORCE_PRIVATE_MAP");
}
