// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include <process_exit.skel.h>
#include "bpf_event_poll.h"
#include "core.h"

static struct process_exit_bpf *obj;
static int perf_output_events;

static int init_bpf_module(const struct bpf_object_open_opts *optsp)
{
	int ret;

	obj = process_exit_bpf__open_opts(optsp);
	if (!obj) {
		BPF_ERR("bpf open failed func=%s\n", __func__);
		return -1;
	}

	ret = process_exit_bpf__load(obj);
	if (ret) {
		BPF_ERR("bpf load failed func=%s\n", __func__);
		return ret;
	}

	perf_output_events = bpf_map__fd(obj->maps.perf_output_events);

	return 0;
}

static void exit_bpf_module(void)
{
	if (obj) {
		bpf_event_poll_unregister(perf_output_events, process_exit_bpf__destroy(obj));
		obj = NULL;
	}
}

BPF_MODULE(process_exit, "4.14");

int setup_process_exit_event(bpf_event_process_fn fn)
{
	if (bpf_event_poll_register(perf_output_events, 4, fn) < 0) {
		BPF_ERR("failed to register\n");
		return -1;
	}

	int ret = process_exit_bpf__attach(obj);
	if (ret) {
		BPF_ERR("bpf attach failed func=%s\n", __func__);
		bpf_event_poll_unregister_no_free(perf_output_events);
		return ret;
	}

	return 0;
}
