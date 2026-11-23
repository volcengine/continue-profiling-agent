// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

/* The capability model: results, caching and names.  No libbpf here. */

#include <cpa_bpf/capabilities.h>

#include <errno.h>
#include <stddef.h>

static void result_from_probe(struct cpa_capability_result *result, int probe_result)
{
	if (probe_result > 0) {
		result->state = CPA_CAP_SUPPORTED;
		result->reason = CPA_CAP_REASON_PROBE_SUCCEEDED;
		result->error_code = 0;
	} else if (probe_result == 0) {
		result->state = CPA_CAP_UNSUPPORTED;
		result->reason = CPA_CAP_REASON_KERNEL_UNSUPPORTED;
		result->error_code = 0;
	} else if (probe_result == -EACCES || probe_result == -EPERM) {
		result->state = CPA_CAP_UNAVAILABLE;
		result->reason = CPA_CAP_REASON_PERMISSION_DENIED;
		result->error_code = -probe_result;
	} else {
		result->state = CPA_CAP_PROBE_ERROR;
		result->reason = CPA_CAP_REASON_PROBE_FAILED;
		result->error_code = -probe_result;
	}
}

const struct cpa_capability_set *cpa_capabilities_detect_once(struct cpa_capability_detector *detector,
							      const struct cpa_capability_probe_ops *ops, void *ctx)
{
	int id;

	if (!detector || !ops || !ops->probe)
		return NULL;
	if (detector->initialized)
		return &detector->capabilities;
	for (id = 0; id < CPA_CAP_COUNT; id++)
		result_from_probe(&detector->capabilities.results[id], ops->probe((enum cpa_capability_id)id, ctx));
	detector->initialized = true;
	return &detector->capabilities;
}

const struct cpa_capability_result *cpa_capabilities_result(const struct cpa_capability_set *set,
							    enum cpa_capability_id id)
{
	if (!set || (int)id < 0 || id >= CPA_CAP_COUNT)
		return NULL;
	return &set->results[id];
}

bool cpa_capability_supported(const struct cpa_capability_set *set, enum cpa_capability_id id)
{
	const struct cpa_capability_result *result = cpa_capabilities_result(set, id);

	return result && result->state == CPA_CAP_SUPPORTED;
}

const char *cpa_capability_id_name(enum cpa_capability_id id)
{
	static const char *const names[] = {
		[CPA_CAP_GET_STACK_PERF_EVENT] = "get_stack_perf_event",
		[CPA_CAP_GET_STACK_KPROBE] = "get_stack_kprobe",
		[CPA_CAP_GET_STACK_TRACEPOINT] = "get_stack_tracepoint",
		[CPA_CAP_PERF_EVENT_PROGRAM_LOAD] = "perf_event_program_load",
		[CPA_CAP_KPROBE_PROGRAM_LOAD] = "kprobe_program_load",
		[CPA_CAP_TRACEPOINT_PROGRAM_LOAD] = "tracepoint_program_load",
		[CPA_CAP_PROCESS_EXIT] = "process_exit",
		[CPA_CAP_COREDUMP] = "coredump",
		[CPA_CAP_RINGBUF] = "ringbuf",
		[CPA_CAP_PAGEFAULT] = "pagefault",
	};

	if ((int)id < 0 || id >= CPA_CAP_COUNT)
		return NULL;
	return names[id];
}

const char *cpa_capability_state_name(enum cpa_capability_state state)
{
	static const char *const names[] = {
		[CPA_CAP_SUPPORTED] = "supported",
		[CPA_CAP_UNSUPPORTED] = "unsupported",
		[CPA_CAP_UNAVAILABLE] = "unavailable",
		[CPA_CAP_PROBE_ERROR] = "probe_error",
	};

	if ((int)state < 0 || state > CPA_CAP_PROBE_ERROR)
		return NULL;
	return names[state];
}

const char *cpa_capability_reason_name(enum cpa_capability_reason reason)
{
	static const char *const names[] = {
		[CPA_CAP_REASON_PROBE_SUCCEEDED] = "probe_succeeded",
		[CPA_CAP_REASON_KERNEL_UNSUPPORTED] = "kernel_unsupported",
		[CPA_CAP_REASON_PERMISSION_DENIED] = "permission_denied",
		[CPA_CAP_REASON_PROBE_FAILED] = "probe_failed",
	};

	if ((int)reason < 0 || reason > CPA_CAP_REASON_PROBE_FAILED)
		return NULL;
	return names[reason];
}
