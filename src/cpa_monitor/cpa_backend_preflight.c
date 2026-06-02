// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "cpa_backend_preflight.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "btf_helpers.h"
#include "cli_cmd_helper.h"
#include "cli_output.h"
#include "trace_helpers.h"

struct cpa_monitor_mode {
	const char *backend;
	const char *probe_name;
	const char *comm;
	const char *btf_path;
	int pid;
	int stack_size;
	bool oneshot;
	bool offcpu;
	bool kernel_stack;
	bool probe_enabled;
	bool comm_filter;
};

static void cpa_mode_init(struct cpa_monitor_mode *mode, void *ctx)
{
	memset(mode, 0, sizeof(*mode));

	mode->backend = get_arg_by_name(ctx, "backend");
	mode->probe_name = get_arg_by_name(ctx, "probe");
	mode->comm = get_arg_by_name(ctx, "comm");
	mode->btf_path = get_arg_by_name(ctx, "btf_path");
	mode->pid = atoi(get_arg_by_name(ctx, "pid"));
	mode->stack_size = atoi(get_arg_by_name(ctx, "stack_size"));
	mode->oneshot = atoi(get_arg_by_name(ctx, "oneshot")) != 0;
	mode->offcpu = atoi(get_arg_by_name(ctx, "offcpu")) != 0;
	mode->kernel_stack = atoi(get_arg_by_name(ctx, "kernel_stack")) != 0;
	mode->probe_enabled = !cli_arg_is_null_default(mode->probe_name);
	mode->comm_filter = !cli_arg_is_null_default(mode->comm);
}

static int cpa_append_reason(char *buf, size_t size, const char *fmt, ...)
{
	size_t used;
	va_list ap;
	int ret;

	if (!buf || size == 0)
		return -EINVAL;

	used = strnlen(buf, size);
	if (used >= size)
		return -ENOSPC;

	va_start(ap, fmt);
	ret = vsnprintf(buf + used, size - used, fmt, ap);
	va_end(ap);

	if (ret < 0)
		return ret;
	if ((size_t)ret >= size - used)
		return -ENOSPC;

	return 0;
}

static int cpa_probe_prog_type(enum bpf_prog_type prog_type, const char *prog_name, char *reason, size_t reason_sz)
{
	int ret = libbpf_probe_bpf_prog_type(prog_type, NULL);

	if (ret > 0)
		return 0;

	cpa_append_reason(reason, reason_sz, "missing BPF program type %s", prog_name);
	return -EOPNOTSUPP;
}

static int cpa_probe_map_type(enum bpf_map_type map_type, const char *map_name, char *reason, size_t reason_sz)
{
	int ret = libbpf_probe_bpf_map_type(map_type, NULL);

	if (ret > 0)
		return 0;

	cpa_append_reason(reason, reason_sz, "missing BPF map type %s", map_name);
	return -EOPNOTSUPP;
}

static int cpa_probe_helper(enum bpf_prog_type prog_type, enum bpf_func_id helper_id, const char *prog_name, const char *helper_name, char *reason, size_t reason_sz)
{
	int ret = libbpf_probe_bpf_helper(prog_type, helper_id, NULL);

	if (ret > 0)
		return 0;

	cpa_append_reason(reason, reason_sz, "missing BPF helper %s for %s programs", helper_name, prog_name);
	return -EOPNOTSUPP;
}

static int cpa_probe_custom_btf(const char *btf_path, char *reason, size_t reason_sz)
{
	struct btf *btf;
	long err;

	if (!btf_path || strcmp(btf_path, "null") == 0)
		return 0;

	if (access(btf_path, R_OK) != 0) {
		cpa_append_reason(reason, reason_sz, "custom BTF path %s is not readable", btf_path);
		return -ENOENT;
	}

	btf = btf__parse(btf_path, NULL);
	err = libbpf_get_error(btf);
	if (err) {
		cpa_append_reason(reason, reason_sz, "custom BTF path %s is not a valid BTF object", btf_path);
		return (int)err;
	}

	btf__free(btf);
	return 0;
}

static int cpa_probe_default_btf(char *reason, size_t reason_sz)
{
	struct bpf_object_open_opts opts = {
		.sz = sizeof(opts),
	};
	int ret;

	ret = ensure_core_btf(&opts);
	if (ret) {
		cpa_append_reason(reason, reason_sz, "failed to resolve BTF required by CO-RE");
		return ret;
	}

	cleanup_core_btf(&opts);
	return 0;
}

static int cpa_probe_btf(const struct cpa_monitor_mode *mode, char *reason, size_t reason_sz)
{
	int ret;

	ret = cpa_probe_custom_btf(mode->btf_path, reason, reason_sz);
	if (ret)
		return ret;

	if (mode->btf_path && strcmp(mode->btf_path, "null") != 0 && access(mode->btf_path, R_OK) == 0)
		return 0;

	return cpa_probe_default_btf(reason, reason_sz);
}

static int cpa_tracepoint_path_exists(const char *category, const char *name)
{
	char path[PATH_MAX];
	const char *bases[] = {
		"/sys/kernel/tracing/events",
		"/sys/kernel/debug/tracing/events",
	};

	for (size_t i = 0; i < sizeof(bases) / sizeof(bases[0]); i++) {
		snprintf(path, sizeof(path), "%s/%s/%s/id", bases[i], category, name);
		if (access(path, R_OK) == 0)
			return 0;
	}

	return -ENOENT;
}

static int cpa_probe_process_exit_support(char *reason, size_t reason_sz)
{
	int ret;

	ret = cpa_probe_prog_type(BPF_PROG_TYPE_TRACEPOINT, "tracepoint", reason, reason_sz);
	if (ret)
		return ret;

	ret = cpa_probe_map_type(BPF_MAP_TYPE_PERF_EVENT_ARRAY, "PERF_EVENT_ARRAY", reason, reason_sz);
	if (ret)
		return ret;

	ret = cpa_probe_helper(BPF_PROG_TYPE_TRACEPOINT, BPF_FUNC_perf_event_output, "tracepoint", "bpf_perf_event_output", reason, reason_sz);
	if (ret)
		return ret;

	ret = cpa_tracepoint_path_exists("sched", "sched_process_exit");
	if (ret) {
		cpa_append_reason(reason, reason_sz, "missing tracepoint sched:sched_process_exit");
		return ret;
	}

	return 0;
}

static int cpa_probe_common_stack_maps(char *reason, size_t reason_sz)
{
	int ret;

	ret = cpa_probe_map_type(BPF_MAP_TYPE_HASH, "HASH", reason, reason_sz);
	if (ret)
		return ret;

	ret = cpa_probe_map_type(BPF_MAP_TYPE_ARRAY, "ARRAY", reason, reason_sz);
	if (ret)
		return ret;

	ret = cpa_probe_map_type(BPF_MAP_TYPE_PERCPU_HASH, "PERCPU_HASH", reason, reason_sz);
	if (ret)
		return ret;

	ret = cpa_probe_map_type(BPF_MAP_TYPE_PERF_EVENT_ARRAY, "PERF_EVENT_ARRAY", reason, reason_sz);
	if (ret)
		return ret;

	return 0;
}

static int cpa_probe_stack_helpers(enum bpf_prog_type prog_type, const char *prog_name, char *reason, size_t reason_sz)
{
	int ret;

	ret = cpa_probe_helper(prog_type, BPF_FUNC_get_stack, prog_name, "bpf_get_stack", reason, reason_sz);
	if (ret)
		return ret;

	ret = cpa_probe_helper(prog_type, BPF_FUNC_perf_event_output, prog_name, "bpf_perf_event_output", reason, reason_sz);
	if (ret)
		return ret;

	ret = cpa_probe_helper(prog_type, BPF_FUNC_probe_read_user, prog_name, "bpf_probe_read_user", reason, reason_sz);
	if (ret)
		return ret;

	ret = cpa_probe_helper(prog_type, BPF_FUNC_probe_read_kernel, prog_name, "bpf_probe_read_kernel", reason, reason_sz);
	if (ret)
		return ret;

	return 0;
}

static int cpa_probe_timer_sampling_support(char *reason, size_t reason_sz)
{
	int ret;

	ret = cpa_probe_common_stack_maps(reason, reason_sz);
	if (ret)
		return ret;

	ret = cpa_probe_prog_type(BPF_PROG_TYPE_PERF_EVENT, "perf_event", reason, reason_sz);
	if (ret)
		return ret;

	return cpa_probe_stack_helpers(BPF_PROG_TYPE_PERF_EVENT, "perf_event", reason, reason_sz);
}

static int cpa_probe_kprobe_sampling_support(char *reason, size_t reason_sz)
{
	int ret;

	ret = cpa_probe_common_stack_maps(reason, reason_sz);
	if (ret)
		return ret;

	ret = cpa_probe_prog_type(BPF_PROG_TYPE_KPROBE, "kprobe", reason, reason_sz);
	if (ret)
		return ret;

	return cpa_probe_stack_helpers(BPF_PROG_TYPE_KPROBE, "kprobe", reason, reason_sz);
}

static int cpa_probe_tracepoint_sampling_support(char *reason, size_t reason_sz)
{
	int ret;

	ret = cpa_probe_common_stack_maps(reason, reason_sz);
	if (ret)
		return ret;

	ret = cpa_probe_prog_type(BPF_PROG_TYPE_TRACEPOINT, "tracepoint", reason, reason_sz);
	if (ret)
		return ret;

	return cpa_probe_stack_helpers(BPF_PROG_TYPE_TRACEPOINT, "tracepoint", reason, reason_sz);
}

static int cpa_probe_offcpu_support(char *reason, size_t reason_sz)
{
	char *probe_func = NULL;
	int ret;

	ret = cpa_probe_kprobe_sampling_support(reason, reason_sz);
	if (ret)
		return ret;

	probe_func = find_kprobe_functions("finish_task_switch");
	if (!probe_func) {
		cpa_append_reason(reason, reason_sz, "missing kprobe target finish_task_switch");
		return -ENOENT;
	}
	free(probe_func);

	return 0;
}

static int cpa_probe_named_probe_support(const struct cpa_monitor_mode *mode, char *reason, size_t reason_sz)
{
	char probe_copy[256];
	char *probe_type;
	char *probe_target;
	char *probe_subtype;
	char *saveptr = NULL;
	int ret;

	if (!mode->probe_enabled)
		return 0;

	if (snprintf(probe_copy, sizeof(probe_copy), "%s", mode->probe_name) >= (int)sizeof(probe_copy)) {
		cpa_append_reason(reason, reason_sz, "probe specification is too long");
		return -ENAMETOOLONG;
	}

	probe_type = strtok_r(probe_copy, ":", &saveptr);
	probe_target = strtok_r(NULL, ":", &saveptr);
	probe_subtype = strtok_r(NULL, ":", &saveptr);

	if (!probe_type) {
		cpa_append_reason(reason, reason_sz, "probe specification is empty");
		return -EINVAL;
	}

	if (strcmp(probe_type, "kprobe") == 0 || strcmp(probe_type, "kretprobe") == 0) {
		ret = cpa_probe_kprobe_sampling_support(reason, reason_sz);
		if (ret)
			return ret;
		if (!probe_target || !kprobe_exists(probe_target)) {
			cpa_append_reason(reason, reason_sz, "missing kprobe target %s", probe_target ? probe_target : "<empty>");
			return -ENOENT;
		}
		return 0;
	}

	if (strcmp(probe_type, "tracepoint") == 0) {
		ret = cpa_probe_tracepoint_sampling_support(reason, reason_sz);
		if (ret)
			return ret;
		if (!probe_target || !probe_subtype) {
			cpa_append_reason(reason, reason_sz, "tracepoint probe must use tracepoint:<group>:<name>");
			return -EINVAL;
		}
		ret = cpa_tracepoint_path_exists(probe_target, probe_subtype);
		if (ret) {
			cpa_append_reason(reason, reason_sz, "missing tracepoint %s:%s", probe_target, probe_subtype);
			return ret;
		}
		return 0;
	}

	cpa_append_reason(reason, reason_sz, "unsupported probe type %s", probe_type);
	return -EINVAL;
}

static int cpa_probe_bpf_runtime(const struct cpa_monitor_mode *mode, char *reason, size_t reason_sz)
{
	int ret;

	reason[0] = '\0';

	ret = cpa_probe_btf(mode, reason, reason_sz);
	if (ret)
		return ret;

	ret = cpa_probe_process_exit_support(reason, reason_sz);
	if (ret)
		return ret;

	if (mode->offcpu)
		return cpa_probe_offcpu_support(reason, reason_sz);

	if (mode->probe_enabled)
		return cpa_probe_named_probe_support(mode, reason, reason_sz);

	return cpa_probe_timer_sampling_support(reason, reason_sz);
}

static bool cpa_perf_mode_uses_bpf_only_features(const struct cpa_monitor_mode *mode)
{
	return mode->oneshot || mode->offcpu || mode->probe_enabled || mode->kernel_stack || mode->pid > 0 || mode->comm_filter || mode->stack_size != 8192;
}

static bool cpa_bpf_mode_can_fallback_to_perf(const struct cpa_monitor_mode *mode)
{
	return !cpa_perf_mode_uses_bpf_only_features(mode);
}

static int cpa_reject_perf_backend(const struct cpa_monitor_mode *mode)
{
	if (!strcmp(mode->backend, "perf") && cpa_perf_mode_uses_bpf_only_features(mode)) {
		CLI_ERROR("perf backend only supports on-cpu continuous profiling; --oneshot, --offcpu, --probe, --pid, --comm, --kernel_stack, and non-default --stack_size require bpf backend");
		return -EINVAL;
	}

	return 0;
}

static int cpa_validate_backend_name(const struct cpa_monitor_mode *mode)
{
	if (!strcmp(mode->backend, "bpf") || !strcmp(mode->backend, "perf"))
		return 0;

	CLI_ERROR("Invalid backend '%s'; backend must be bpf or perf", mode->backend);
	return -EINVAL;
}

int cpa_monitor_prepare_backend(void *ctx)
{
	struct cpa_monitor_mode mode;
	char reason[512];
	int ret;

	if (!ctx)
		return -EINVAL;

	cpa_mode_init(&mode, ctx);

	ret = cpa_validate_backend_name(&mode);
	if (ret)
		return ret;

	ret = cpa_reject_perf_backend(&mode);
	if (ret)
		return ret;

	if (strcmp(mode.backend, "bpf") != 0)
		return 0;

	ret = cpa_probe_bpf_runtime(&mode, reason, sizeof(reason));
	if (!ret)
		return 0;

	if (!cpa_bpf_mode_can_fallback_to_perf(&mode)) {
		CLI_ERROR("BPF capability check failed: %s. Requested mode requires BPF backend and cannot fall back to perf; perf backend only supports on-cpu continuous profiling.", reason);
		return ret;
	}

	ret = set_arg_by_name(ctx, "backend", "perf");
	if (ret) {
		CLI_ERROR("BPF capability check failed: %s. Failed to switch backend to perf.", reason);
		return ret;
	}

	CLI_ERROR("WARNING: BPF capability check failed: %s. Falling back to perf backend; perf only supports on-cpu continuous profiling and provides no IRQOFF records.", reason);
	return 0;
}
