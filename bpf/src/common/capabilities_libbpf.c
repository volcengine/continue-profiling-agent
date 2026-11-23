// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

/* The capabilities of the running kernel, each probed by loading with libbpf. */

#include <cpa_bpf/capabilities.h>

#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "core.h"
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

/* The type @id resolves to, past typedefs and qualifiers. */
static const struct btf_type *btf_resolved(const struct btf *btf, __u32 id)
{
	const struct btf_type *t = btf__type_by_id(btf, id);

	while (t && (btf_is_typedef(t) || btf_is_mod(t)))
		t = btf__type_by_id(btf, t->type);
	return t;
}

/* The member @name of @t, also inside its anonymous structs and unions. */
static const struct btf_type *btf_member_type(const struct btf *btf, const struct btf_type *t, const char *name,
					      int depth)
{
	const struct btf_member *m = btf_members(t);
	const struct btf_type *found;
	const struct btf_type *mt;
	unsigned int i;

	for (i = 0; depth < 4 && i < btf_vlen(t); i++, m++) {
		mt = btf_resolved(btf, m->type);
		if (!mt)
			continue;
		if (m->name_off) {
			if (!strcmp(btf__name_by_offset(btf, m->name_off), name))
				return mt;
		} else if (btf_is_composite(mt)) {
			found = btf_member_type(btf, mt, name, depth + 1);
			if (found)
				return found;
		}
	}
	return NULL;
}

static bool btf_member_is_int(const struct btf *btf, const struct btf_type *t, const char *name)
{
	const struct btf_type *mt = btf_member_type(btf, t, name, 0);

	return mt && btf_is_int(mt);
}

/* The struct folio and enum pageflags pf_new_anon_folio reads. */
static const char *pagefault_folio_layout(const struct btf *btf)
{
	const struct btf_type *t;
	const struct btf_enum *e;
	unsigned int i;
	int id;

	id = btf__find_by_name_kind(btf, "pageflags", BTF_KIND_ENUM);
	t = id > 0 ? btf__type_by_id(btf, id) : NULL;
	for (i = 0, e = t ? btf_enum(t) : NULL; t && i < btf_vlen(t); i++, e++)
		if (!strcmp(btf__name_by_offset(btf, e->name_off), "PG_head"))
			break;
	if (!t || i == btf_vlen(t))
		return "the kernel BTF has no PG_head in enum pageflags";
	id = btf__find_by_name_kind(btf, "folio", BTF_KIND_STRUCT);
	t = id > 0 ? btf__type_by_id(btf, id) : NULL;
	if (!t)
		return "the kernel BTF has no struct folio";
	/* 6.18 wraps the page flags in memdesc_flags_t */
	if (!btf_member_is_int(btf, t, "flags"))
		return "struct folio has no flags word (a layout newer than this build knows)";
	if (!btf_member_is_int(btf, t, "_folio_order") && !btf_member_is_int(btf, t, "_flags_1"))
		return "struct folio has neither _folio_order nor _flags_1 (a layout newer than this build knows)";
	return NULL;
}

/*
 * The kernel series the folio entry of --pagefault was run on.  Others with
 * the layout it reads are accepted, with a warning: a series may add a way
 * for memory to go that no hook follows (6.13 has two).
 */
#define PF_VERIFIED_FOLIO_KERNELS "6.6, 6.8"

static bool pagefault_folio_series_verified(void)
{
	static const unsigned int series[] = {
		KERNEL_VERSION(6, 6, 0),
		KERNEL_VERSION(6, 8, 0),
	};
	unsigned int v = get_kernel_version() & ~0xffU;

	for (unsigned int i = 0; i < sizeof(series) / sizeof(series[0]); i++)
		if (v == series[i])
			return true;
	return false;
}

/*
 * The one place that decides how --pagefault sees a new anonymous page:
 *
 *   - before 5.4, refused: a perf output into a full buffer fails there
 *     without telling the BPF program (perf_event_output() returned
 *     nothing), so a sampled page could be lost without being counted.
 *   - folio_add_new_anon_rmap in the kernel (6.3+): only that, and the
 *     folio's size read through the kernel BTF.  On 6.3 - 6.7 the old
 *     page_add_new_anon_rmap still exists as its wrapper, called by a few
 *     paths only: both attached would count those pages twice.
 *   - otherwise page_add_new_anon_rmap with its compound argument, which
 *     5.19 removed (40f2bbf71161): the vmlinux BTF has the prototype, a
 *     kernel without one (ESRCH from libbpf: no CONFIG_DEBUG_INFO_BTF) is
 *     told by version.
 *   - otherwise refused.  5.19 - 6.2 tell a THP only by its page flags: not
 *     supported.
 */
static void pagefault_rmap_decide(struct cpa_pagefault_rmap *r)
{
	const char *syms[] = { "folio_add_new_anon_rmap", "page_add_new_anon_rmap" };
	unsigned long addr;
	bool folio, page;
	struct btf *vmlinux;
	int err, id, four, n;

	r->entry = CPA_PF_ENTRY_NONE;
	r->symbol = NULL;
	r->error = 0;
	r->unverified = NULL;
	if (get_kernel_version() < KERNEL_VERSION(5, 4, 0)) {
		r->why = "--pagefault needs Linux 5.4 or later: before 5.4 a full perf buffer drops sampled pages "
			 "without the BPF program seeing it, so the live set could be under-counted without an "
			 "INCOMPLETE report";
		return;
	}
	/*
	 * By name, whatever the address: with kptr_restrict=2 /proc/kallsyms
	 * lists every address as 0, and the kprobe attaches by name all the
	 * same.  (Not the ftrace list either: a kprobe needs no ftrace site.)
	 */
	n = find_ksyms_addr(&syms[0], &addr, 1);
	folio = n == 1;
	page = n == 0 && find_ksyms_addr(&syms[1], &addr, 1) == 1;
	if (n < 0) {
		r->why = "cannot read /proc/kallsyms";
		r->error = errno ? errno : EIO;
		return;
	}
	vmlinux = btf__load_vmlinux_btf();
	err = errno;	/* before any other call can overwrite it */
	if (folio) {
		r->symbol = syms[0];
		if (!vmlinux) {
			r->why = "folio_add_new_anon_rmap needs the kernel BTF (CONFIG_DEBUG_INFO_BTF) to read the "
				 "size of a folio";
			r->error = err == ESRCH ? 0 : err;
			return;
		}
		r->why = pagefault_folio_layout(vmlinux);
		if (!r->why)
			r->entry = CPA_PF_ENTRY_FOLIO;
		if (!r->why && !pagefault_folio_series_verified())
			r->unverified = "this kernel series has not been verified with --pagefault (verified: "
					PF_VERIFIED_FOLIO_KERNELS "); totals may miss releases it added";
		btf__free(vmlinux);
		return;
	}
	if (!page) {
		btf__free(vmlinux);
		r->why = "neither folio_add_new_anon_rmap nor page_add_new_anon_rmap is available on this kernel";
		return;
	}
	r->symbol = syms[1];
	if (!vmlinux && err != ESRCH) {
		r->why = "cannot read the kernel BTF";
		r->error = err;
		return;
	}
	four = get_kernel_version() < KERNEL_VERSION(5, 19, 0);
	id = vmlinux ? btf__find_by_name_kind(vmlinux, "page_add_new_anon_rmap", BTF_KIND_FUNC) : -ENOENT;
	if (id > 0) {
		const struct btf_type *fn = btf__type_by_id(vmlinux, id);
		const struct btf_type *proto = btf__type_by_id(vmlinux, fn->type);

		four = proto && btf_vlen(proto) == 4;
	}
	btf__free(vmlinux);
	if (four)
		r->entry = CPA_PF_ENTRY_PAGE;
	else
		r->why = "page_add_new_anon_rmap without its compound argument (5.19 - 6.2) is not supported";
}

static struct cpa_pagefault_rmap pagefault_rmap;

static void pagefault_rmap_decide_once(void)
{
	pagefault_rmap_decide(&pagefault_rmap);
}

const struct cpa_pagefault_rmap *cpa_pagefault_rmap(void)
{
	static pthread_once_t once = PTHREAD_ONCE_INIT;

	pthread_once(&once, pagefault_rmap_decide_once);
	return &pagefault_rmap;
}

static int probe_pagefault(void)
{
	const struct cpa_pagefault_rmap *rmap = cpa_pagefault_rmap();

	if (rmap->entry != CPA_PF_ENTRY_NONE)
		return 1;
	return rmap->error ? -rmap->error : 0;
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
	case CPA_CAP_PAGEFAULT:
		return probe_pagefault();
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
