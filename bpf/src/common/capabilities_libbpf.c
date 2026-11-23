// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

/* The capabilities of the running kernel, each probed by loading with libbpf. */

#include <cpa_bpf/capabilities.h>

#include <errno.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "trace_helpers.h"

static int probe_program_type(enum bpf_prog_type type)
{
	return libbpf_probe_bpf_prog_type(type, NULL);
}

/* The kprobe on do_coredump that --enable_coredump_capture attaches. */
static int probe_coredump(void)
{
	int ret = probe_program_type(BPF_PROG_TYPE_KPROBE);

	if (ret != 1)
		return ret;
	return kprobe_exists("do_coredump") ? 1 : 0;
}

/*
 * libbpf's probes cannot tell "no permission" from "the kernel lacks it": a
 * refused helper probe reads as supported, a refused program type as
 * missing.  So first load the smallest tracing program: refused with EPERM
 * or EACCES, every capability is reported as denied instead.
 */
static int probe_permission(void)
{
	const struct bpf_insn insns[] = {
		{ .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0 },
		{ .code = BPF_JMP | BPF_EXIT },
	};
	int fd, err;

	fd = bpf_prog_load(BPF_PROG_TYPE_TRACEPOINT, NULL, "GPL", insns, sizeof(insns) / sizeof(insns[0]), NULL);
	if (fd >= 0) {
		close(fd);
		return 0;
	}
	err = errno;
	return err == EPERM || err == EACCES ? -err : 0;
}

static int libbpf_probe(enum cpa_capability_id id, void *ctx)
{
	int denied = *(const int *)ctx;

	if (denied)
		return denied;
	switch (id) {
	case CPA_CAP_GET_STACK_PERF_EVENT:
		return libbpf_probe_bpf_helper(BPF_PROG_TYPE_PERF_EVENT, BPF_FUNC_get_stack, NULL);
	case CPA_CAP_GET_STACK_KPROBE:
		return libbpf_probe_bpf_helper(BPF_PROG_TYPE_KPROBE, BPF_FUNC_get_stack, NULL);
	case CPA_CAP_GET_STACK_TRACEPOINT:
		return libbpf_probe_bpf_helper(BPF_PROG_TYPE_TRACEPOINT, BPF_FUNC_get_stack, NULL);
	case CPA_CAP_PERF_EVENT_PROGRAM_LOAD:
		return probe_program_type(BPF_PROG_TYPE_PERF_EVENT);
	case CPA_CAP_KPROBE_PROGRAM_LOAD:
		return probe_program_type(BPF_PROG_TYPE_KPROBE);
	case CPA_CAP_TRACEPOINT_PROGRAM_LOAD:
		return probe_program_type(BPF_PROG_TYPE_TRACEPOINT);
	case CPA_CAP_PROCESS_EXIT:
		return probe_program_type(BPF_PROG_TYPE_TRACEPOINT);
	case CPA_CAP_COREDUMP:
		return probe_coredump();
	case CPA_CAP_RINGBUF:
		return libbpf_probe_bpf_map_type(BPF_MAP_TYPE_RINGBUF, NULL);
	case CPA_CAP_COUNT:
		break;
	}
	return -EINVAL;
}

const struct cpa_capability_set *cpa_capabilities_get(void)
{
	static struct cpa_capability_detector detector;
	static const struct cpa_capability_probe_ops ops = {
		.probe = libbpf_probe,
	};

	int denied = 0;

	if (!detector.initialized)
		denied = probe_permission();
	return cpa_capabilities_detect_once(&detector, &ops, &denied);
}
