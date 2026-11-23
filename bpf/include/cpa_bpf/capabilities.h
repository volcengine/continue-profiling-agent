// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

/*
 * What the running kernel lets the capture modules do, probed once and
 * cached.  Capture code asks for a named fact instead of comparing kernel
 * versions; `cpa capabilities` prints the same facts.
 */

#ifndef CPA_BPF_CAPABILITIES_H
#define CPA_BPF_CAPABILITIES_H

#include <stdbool.h>

enum cpa_capability_id {
	CPA_CAP_GET_STACK_PERF_EVENT,
	CPA_CAP_GET_STACK_KPROBE,
	CPA_CAP_GET_STACK_TRACEPOINT,
	CPA_CAP_PERF_EVENT_PROGRAM_LOAD,
	CPA_CAP_KPROBE_PROGRAM_LOAD,
	CPA_CAP_TRACEPOINT_PROGRAM_LOAD,
	CPA_CAP_PROCESS_EXIT,
	CPA_CAP_COREDUMP,
	CPA_CAP_RINGBUF,
	CPA_CAP_COUNT,
};

enum cpa_capability_state {
	CPA_CAP_SUPPORTED,
	CPA_CAP_UNSUPPORTED,
	CPA_CAP_UNAVAILABLE,
	CPA_CAP_PROBE_ERROR,
};

enum cpa_capability_reason {
	CPA_CAP_REASON_PROBE_SUCCEEDED,
	CPA_CAP_REASON_KERNEL_UNSUPPORTED,
	CPA_CAP_REASON_PERMISSION_DENIED,
	CPA_CAP_REASON_PROBE_FAILED,
};

struct cpa_capability_result {
	enum cpa_capability_state state;
	enum cpa_capability_reason reason;
	int error_code;
};

struct cpa_capability_set {
	struct cpa_capability_result results[CPA_CAP_COUNT];
};

/* > 0 supported, 0 the kernel lacks it, < 0 a negative errno. */
typedef int (*cpa_capability_probe_fn)(enum cpa_capability_id id, void *ctx);

struct cpa_capability_probe_ops {
	cpa_capability_probe_fn probe;
};

struct cpa_capability_detector {
	bool initialized;
	struct cpa_capability_set capabilities;
};

/* Probe every capability on the first call; later calls return the cache. */
const struct cpa_capability_set *cpa_capabilities_detect_once(struct cpa_capability_detector *detector,
							      const struct cpa_capability_probe_ops *ops, void *ctx);

/* The capabilities of the running kernel, probed with libbpf. */
const struct cpa_capability_set *cpa_capabilities_get(void);

const struct cpa_capability_result *cpa_capabilities_result(const struct cpa_capability_set *set,
							    enum cpa_capability_id id);
bool cpa_capability_supported(const struct cpa_capability_set *set, enum cpa_capability_id id);
const char *cpa_capability_id_name(enum cpa_capability_id id);
const char *cpa_capability_state_name(enum cpa_capability_state state);
const char *cpa_capability_reason_name(enum cpa_capability_reason reason);

#endif
