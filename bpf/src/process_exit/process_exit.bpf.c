// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <linux/version.h>
#include "core_fixes.bpf.h"
#include <cpa_bpf/bpf_event.h>

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} perf_output_events SEC(".maps");

SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit_tp(struct trace_event_raw_sched_process_template *ctx)
{
	struct process_exit_event event = { 0 };

	unsigned long long pid_tgid = bpf_get_current_pid_tgid();

	unsigned int tgid = pid_tgid >> 32;
	unsigned int pid = bpf_get_current_pid_tgid();

	if (tgid != pid)
		return 0;

	event.pid = tgid;
	event.ts = bpf_ktime_get_ns();

	bpf_perf_event_output(ctx, &perf_output_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
