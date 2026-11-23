// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

/*
 * cpa monitor --pagefault: resident anonymous memory of one process.
 *
 * Kernel side (stack_capture_pagefault variant): every new anonymous page
 * of the target is judged, 1 in N 4 KiB pages (by address hash), larger
 * folios in proportion to their size and every THP are sampled with their
 * stack; releases and moves of address ranges
 * are reported.  This file turns that into the live set: the tracker
 * (cpa_pagefault_tracker.c) keeps the sampled pages still mapped and
 * the bytes per stack, and every runtime tick writes the per-stack bytes
 * into the second's bucket.  Nothing else runs periodically.
 *
 * The process is --pid, or the one a rule selection latches with
 * --first_match (cold start): target_ctl puts it into the shared target
 * set at its exec, and the kernel side follows it from there.
 *
 * Pages already resident when profiling starts are found once in
 * /proc/<pid>/pagemap with the same hash and charged to
 * "[resident before profiling]".  A --first_match process has none: its
 * address space is created by the exec that selects it.
 */

#include "cpa_pagefault.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

#include <cpa_bpf.h>
#include <cpa_bpf/capabilities.h>

#include "cli_common.h"
#include "cli_stackmap.h"
#include "stackmap_timewheel.h"
#include "cpa_pagefault_tracker.h"
#include "cpa_runtime.h"
#include "cpa_target_ctl.h"
#include "cpa_unwinder.h"

#define PF_DEFAULT_SAMPLE_PAGES 16
#define PF_MARKER_BEFORE "[resident before profiling]"
#define PF_MARKER_DROPPED "[stack dropped]"
/*
 * Address-space events of different CPUs reach userspace in any order,
 * within the latency of the poll thread: they are applied in time order
 * once this much older than the newest one.
 */
#define PF_REORDER_NS (200 * 1000000ULL)
/* pagemap entries read per pread */
#define PF_PAGEMAP_BATCH 512
#define PF_PAGEMAP_PRESENT (1ULL << 63)
#define PF_PAGEMAP_PFN ((1ULL << 55) - 1)

/* What went wrong so far; a change means the live set is no longer exact. */
struct pf_losses {
	uint64_t pages, releases;	/* the kernel had no buffer room */
	uint64_t unseen;	/* records the kernel dropped, BPF unaware */
	uint64_t late_unknown, out_of_order, failed, unwritten;
	uint64_t unknown_folios;	/* new pages of a size not believed */
};

static struct {
	bool enabled;
	bool active;		/* charges accepted: from configure/restore to pause */
	bool markers;		/* ids_before and ids_dropped are interned */
	bool cold_start;	/* --first_match: tracked from its exec */
	int pid;		/* 0 until the --first_match winner is known */
	uint32_t sample_pages;
	uint64_t salt;

	pthread_mutex_t lock;	/* tracker, marker ids; before the tracemap lock */
	struct pf_tracker *tracker;
	uint32_t ids_before;
	uint32_t ids_dropped;
	uint64_t lost;		/* charged to [stack dropped] */
	uint64_t unwritten;	/* snapshot entries the storage refused */
	uint64_t written_sec;	/* the bucket last written (UINT64_MAX: none) */
	uint64_t kernel_lost_stack;	/* records of full perf buffers */
	uint64_t kernel_lost_events;
	struct pf_losses losses;	/* as last reported */
	uint64_t baseline_pages;
	uint64_t zero_pfn, huge_zero_pfn;
} pf = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.written_sec = UINT64_MAX,
};

static uint64_t mono_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static uint64_t sample_bytes(uint32_t weight)
{
	return (uint64_t)weight * PF_PAGE_SIZE;
}

bool cpa_pagefault_enabled(void)
{
	return pf.enabled;
}

/* ----------------------------------------------------------- markers -- */

static int target_pid_locked(void)
{
	if (!pf.pid)
		pf.pid = (int)cpa_target_latched_pid();
	return pf.pid;
}

/* The two stacks without a captured stack, rooted like the target's. */
static void intern_markers_locked(const struct stack_sample *root)
{
	pf.markers = !cpa_unwind_intern_marker(root, PF_MARKER_BEFORE,
						    &pf.ids_before) &&
		     !cpa_unwind_intern_marker(root, PF_MARKER_DROPPED,
						    &pf.ids_dropped);
}

/* Without a sample of the target at hand: its pid and comm. */
static void intern_markers_from_proc_locked(void)
{
	struct stack_sample *root = calloc(1, sizeof(*root));
	char path[64];
	FILE *fp;

	if (!root)
		return;
	root->pid = target_pid_locked();
	stack_sample_set_process(root, root->pid, 0);
	snprintf(path, sizeof(path), "/proc/%d/comm", root->pid);
	fp = root->pid ? fopen(path, "r") : NULL;
	if (fp) {
		if (fgets(root->comm, sizeof(root->comm), fp))
			root->comm[strcspn(root->comm, "\n")] = '\0';
		fclose(fp);
	}
	memcpy(root->group_comm, root->comm, sizeof(root->comm));
	if (root->pid)
		intern_markers_locked(root);
	free(root);
}

/* ------------------------------------------------------------ events -- */

void cpa_pagefault_on_alloc(const struct stack_sample *sample,
				 uint32_t ids_id)
{
	pthread_mutex_lock(&pf.lock);
	if (pf.active) {
		/* a --first_match target is first seen here */
		if (!pf.markers)
			intern_markers_locked(sample);
		pf_tracker_alloc(pf.tracker, sample->timestamp, sample->pf.addr,
				 sample->pf.pages, sample_bytes(sample->pf.weight),
				 ids_id);
	}
	pthread_mutex_unlock(&pf.lock);
}

/* A sampled page without its stack still counts. */
static void charge_dropped_locked(uint64_t ts, uint64_t addr, uint32_t pages,
				  uint32_t weight)
{
	pf.lost++;
	if (!pf.markers)
		intern_markers_from_proc_locked();
	/* no root to charge it to (target gone): counted in lost only */
	if (pf.markers)
		pf_tracker_alloc(pf.tracker, ts, addr, pages, sample_bytes(weight),
				 pf.ids_dropped);
}

void cpa_pagefault_on_lost(const struct pf_sample_meta *meta, uint64_t ts)
{
	pthread_mutex_lock(&pf.lock);
	if (pf.active)
		charge_dropped_locked(ts, meta->addr, meta->pages, meta->weight);
	pthread_mutex_unlock(&pf.lock);
}

static void release_event_cb(void *data, unsigned int size, void *user_ctx)
{
	const struct pf_release_event *ev = data;

	(void)user_ctx;
	if (size < sizeof(*ev))
		return;
	pthread_mutex_lock(&pf.lock);
	if (pf.active) {
		switch (ev->kind) {
		case PF_RELEASE:
		case PF_MOVE:
		case PF_RESET:
			pf_tracker_submit(pf.tracker, (enum pf_event_kind)ev->kind,
					  ev->ts, ev->start, ev->end, ev->new_start);
			if (ev->kind == PF_RESET)
				CLI_OUTPUT("pagefault: pid %d exec'ed or exited, live "
					   "set cleared", target_pid_locked());
			/* what the other CPUs' buffers can still bring is newer */
			pf_tracker_flush(pf.tracker, ev->ts - PF_REORDER_NS);
			break;
		case PF_DROPPED:
			charge_dropped_locked(ev->ts, ev->start,
					      (uint32_t)((ev->end - ev->start) >>
							 PF_PAGE_SHIFT),
					      ev->weight);
			break;
		}
	}
	pthread_mutex_unlock(&pf.lock);
}

/* Records of a full perf buffer, known here only (poll thread). */
static void stack_records_lost(int cpu, unsigned long long n)
{
	(void)cpu;
	pthread_mutex_lock(&pf.lock);
	pf.kernel_lost_stack += n;
	pthread_mutex_unlock(&pf.lock);
}

static void event_records_lost(int cpu, unsigned long long n)
{
	(void)cpu;
	pthread_mutex_lock(&pf.lock);
	pf.kernel_lost_events += n;
	pthread_mutex_unlock(&pf.lock);
}

/* ---------------------------------------------------------- snapshot -- */

struct snapshot_ctx {
	struct cli_stackmap *map;
	uint64_t record_ms;
};

static void snapshot_stack(uint32_t stack, uint64_t bytes, void *arg)
{
	struct snapshot_ctx *ctx = arg;

	if (cli_stackmap_add_at(ctx->map, stack, bytes, ctx->record_ms))
		pf.unwritten++;
}

/*
 * Reported when it happens: from then on the live set is wrong by an
 * amount that cannot be told (a lost release keeps pages for good).  One
 * map lookup per tick.
 */
static uint64_t beyond(uint64_t total, uint64_t known)
{
	return total > known ? total - known : 0;
}

static void check_losses_locked(void)
{
	struct pf_tracker_stats st;
	struct pf_losses now = pf.losses;
	struct pf_state bpf;

	/* kept as last read once the BPF object is gone */
	if (!stack_capture_pagefault_state(&bpf)) {
		now.pages = bpf.lost_pages;
		now.releases = bpf.lost_releases;
		now.unknown_folios = bpf.unknown_folios;
		/* the kernel's count arrives after BPF's: never ahead of it
		 * where BPF saw the failure */
		now.unseen = beyond(pf.kernel_lost_stack, bpf.failed_stack_outputs) +
			     beyond(pf.kernel_lost_events, bpf.failed_event_outputs);
	}
	pf_tracker_get_stats(pf.tracker, &st);
	now.late_unknown = st.late_unknown;
	now.out_of_order = st.out_of_order;
	now.failed = st.failed;
	now.unwritten = pf.unwritten;
	if (memcmp(&now, &pf.losses, sizeof(now)))
		CLI_ERROR("pagefault: INCOMPLETE: the live set is no longer exact: "
			  "unreported sampled pages=%llu KiB, unreported releases=%llu, "
			  "records dropped by full buffers=%llu, "
			  "allocations older than the event log=%llu, events past the "
			  "reorder window=%llu, out of memory=%llu, stacks not "
			  "written=%llu, new pages of an unknown size=%llu",
			  (unsigned long long)(now.pages * PF_PAGE_SIZE / 1024),
			  (unsigned long long)now.releases,
			  (unsigned long long)now.unseen,
			  (unsigned long long)now.late_unknown,
			  (unsigned long long)now.out_of_order,
			  (unsigned long long)now.failed,
			  (unsigned long long)now.unwritten,
			  (unsigned long long)now.unknown_folios);
	pf.losses = now;
}

/*
 * The live set at this tick, written into its second.  Values of a second
 * add up: a late tick landing in the second of the previous one must not
 * write it twice.
 */
static void cpa_pagefault_timer_fn(void *worker_ctx)
{
	struct snapshot_ctx ctx;

	(void)worker_ctx;
	pthread_mutex_lock(&pf.lock);
	if (pf.active) {
		pf_tracker_flush(pf.tracker, mono_ns() - PF_REORDER_NS);
		check_losses_locked();
		ctx.map = cpa_main_tracemap_get_and_lock();
		ctx.record_ms = cli_stackmap_now_record_ms(ctx.map);
		if (ctx.record_ms / STACKMAP_TIMEWHEEL_BUCKET_MS != pf.written_sec) {
			pf_tracker_for_each_stack(pf.tracker, snapshot_stack, &ctx);
			pf.written_sec = ctx.record_ms / STACKMAP_TIMEWHEEL_BUCKET_MS;
		}
		cpa_main_tracemap_unlock();
	}
	pthread_mutex_unlock(&pf.lock);
}

/* ---------------------------------------------------------- baseline -- */

/* An anonymous private mapping: no file, not shared, not a kernel special. */
static bool anon_private_vma(const char *perms, unsigned long inode,
			     const char *path)
{
	if (perms[3] != 'p' || inode)
		return false;
	return !path[0] || strcmp(path, "[heap]") == 0 ||
	       strncmp(path, "[stack", 6) == 0 || strncmp(path, "[anon:", 6) == 0;
}

/* The page frame of a byte of our own, read after touching it for reading. */
static uint64_t own_pfn(int pagemap, const volatile char *p)
{
	uint64_t entry = 0;

	(void)*p;
	if (pread(pagemap, &entry, sizeof(entry),
		  (off_t)((uintptr_t)p / PF_PAGE_SIZE * sizeof(entry))) != sizeof(entry) ||
	    !(entry & PF_PAGEMAP_PRESENT))
		return 0;
	return entry & PF_PAGEMAP_PFN;
}

/*
 * Reading untouched anonymous memory maps the shared zero page (or the
 * huge zero page): present in pagemap, but no page of the process and
 * never a new anonymous page.  Learn their frames from our own reads.
 */
static void find_zero_pfns(void)
{
	int pagemap = open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);
	char *area = mmap(NULL, 2 * PF_THP_SIZE, PROT_READ,
			  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	pf.zero_pfn = pf.huge_zero_pfn = 0;
	if (pagemap >= 0 && area != MAP_FAILED) {
		char *huge = (char *)(((uintptr_t)area + PF_THP_SIZE - 1) &
				      ~(uintptr_t)(PF_THP_SIZE - 1));

		pf.zero_pfn = own_pfn(pagemap, area);
		madvise(huge, PF_THP_SIZE, MADV_HUGEPAGE);
		pf.huge_zero_pfn = own_pfn(pagemap, huge);
		if (pf.huge_zero_pfn == pf.zero_pfn)
			pf.huge_zero_pfn = 0;	/* no huge zero page in use */
	}
	if (area != MAP_FAILED)
		munmap(area, 2 * PF_THP_SIZE);
	if (pagemap >= 0)
		close(pagemap);
	if (!pf.zero_pfn)
		CLI_ERROR("pagefault: page frames are not visible (no CAP_SYS_ADMIN?): "
			  "zero pages read by the target count as resident");
}

static bool zero_page(uint64_t entry)
{
	uint64_t pfn = entry & PF_PAGEMAP_PFN;

	return pfn && (pfn == pf.zero_pfn ||
		       (pf.huge_zero_pfn && pfn >= pf.huge_zero_pfn &&
			pfn < pf.huge_zero_pfn + PF_THP_PAGES));
}

/*
 * Charge the sampled pages already resident to the "before" marker.  A
 * target whose pages cannot be read (gone, no permission) fails the start.
 */
static int scan_resident_pages(void)
{
	uint64_t entries[PF_PAGEMAP_BATCH];
	uint64_t ts = mono_ns(), found = 0;
	char path[64], line[512];
	FILE *maps;
	int pagemap, ret = 0;

	find_zero_pfns();
	snprintf(path, sizeof(path), "/proc/%d/maps", pf.pid);
	maps = fopen(path, "r");
	snprintf(path, sizeof(path), "/proc/%d/pagemap", pf.pid);
	pagemap = open(path, O_RDONLY | O_CLOEXEC);
	if (!maps || pagemap < 0) {
		ret = -errno;
		CLI_ERROR("pagefault: cannot read the pages of pid %d: %s", pf.pid,
			  strerror(errno));
		goto out;
	}
	while (fgets(line, sizeof(line), maps)) {
		unsigned long start, end, inode;
		char perms[8] = "", name[256] = "";

		if (sscanf(line, "%lx-%lx %7s %*s %*s %lu %255s", &start, &end,
			   perms, &inode, name) < 4 ||
		    !anon_private_vma(perms, inode, name))
			continue;
		for (uint64_t addr = start; addr < end;) {
			uint64_t n = (end - addr) / PF_PAGE_SIZE;
			ssize_t got;

			if (n > PF_PAGEMAP_BATCH)
				n = PF_PAGEMAP_BATCH;
			got = pread(pagemap, entries, n * sizeof(entries[0]),
				    (off_t)(addr / PF_PAGE_SIZE * sizeof(entries[0])));
			if (got <= 0) {
				ret = got ? -errno : -ESRCH;	/* gone meanwhile */
				CLI_ERROR("pagefault: reading the pages of pid %d "
					  "failed: %s", pf.pid, strerror(-ret));
				goto out;
			}
			n = (uint64_t)got / sizeof(entries[0]);
			for (uint64_t i = 0; i < n; i++, addr += PF_PAGE_SIZE) {
				if (!(entries[i] & PF_PAGEMAP_PRESENT) ||
				    zero_page(entries[i]) ||
				    !pf_page_sampled(addr, pf.salt, pf.sample_pages - 1))
					continue;
				pf_tracker_alloc(pf.tracker, ts, addr, 1,
						 sample_bytes(pf.sample_pages),
						 pf.ids_before);
				found++;
			}
		}
	}
	pf.baseline_pages = found;
	CLI_OUTPUT("pagefault: %llu sampled pages already resident (~%llu KiB) "
		   "charged to " PF_MARKER_BEFORE " in %llums",
		   (unsigned long long)found,
		   (unsigned long long)(found * pf.sample_pages * PF_PAGE_SIZE / 1024),
		   (unsigned long long)((mono_ns() - ts) / 1000000ULL));
out:
	if (maps)
		fclose(maps);
	if (pagemap >= 0)
		close(pagemap);
	return ret;
}

/*
 * What the target has resident now goes to the "before" marker.  A
 * --first_match target not latched yet has nothing; its markers come with
 * its first sample.
 */
static int charge_resident_locked(void)
{
	if (!target_pid_locked())
		return 0;
	if (!pf.markers)
		intern_markers_from_proc_locked();
	return pf.markers ? scan_resident_pages() : -ESRCH;
}

/* ------------------------------------------------------------ config -- */

int cpa_pagefault_configure(void *cli_ctx)
{
	const struct cpa_target_spec *spec = cpa_target_spec();
	const struct cpa_pagefault_rmap *rmap;
	struct stack_capture_pagefault_cfg cfg = { 0 };
	long pages;

	pf.enabled = atoi(get_arg_by_name(cli_ctx, "pagefault")) != 0;
	pf.cold_start = false;
	if (!pf.enabled)
		return 0;

	/*
	 * The kernel first, decided in one place (cpa_pagefault_rmap()):
	 * before 5.4 a perf output into a full buffer fails without telling
	 * the BPF program, so a sampled page lost there would be neither
	 * charged to [stack dropped] nor counted; 5.19 - 6.2 cannot tell a
	 * THP; 6.3+ needs the kernel BTF to read a folio's size.
	 */
	rmap = cpa_pagefault_rmap();
	if (rmap->entry == CPA_PF_ENTRY_NONE) {
		if (rmap->error)
			CLI_ERROR("%s (error %d)", rmap->why, rmap->error);
		else
			CLI_ERROR("%s", rmap->why);
		return -ENOTSUP;
	}

	pages = atol(get_arg_by_name(cli_ctx, "pf_sample_pages"));
	if (pages <= 0 || pages > PF_SAMPLE_PAGES_MAX || (pages & (pages - 1))) {
		CLI_ERROR("--pf_sample_pages must be a power of two from 1 to %d",
			  PF_SAMPLE_PAGES_MAX);
		return -EINVAL;
	}
	/* the page constants are those of 4 KiB pages, folios up to 2 MiB */
	if (sysconf(_SC_PAGESIZE) != PF_PAGE_SIZE) {
		CLI_ERROR("--pagefault needs a kernel with 4 KiB pages");
		return -ENOTSUP;
	}
	/* a snapshot per tick is the live set of that second */
	if (atoi(get_arg_by_name(cli_ctx, "record_interval")) != 1) {
		CLI_ERROR("--pagefault needs --record_interval=1");
		return -EINVAL;
	}
	/* the page's stack is the user stack */
	if (atoi(get_arg_by_name(cli_ctx, "kernel_stack"))) {
		CLI_ERROR("--pagefault cannot be combined with --kernel_stack");
		return -EINVAL;
	}
	/* one process: --pid, or the first to exec that matches the rules */
	if (spec->mode == CPA_TARGET_LEGACY ?
	    spec->legacy_pid <= 0 || spec->legacy_thread_comm[0] :
	    !spec->first_match || spec->children || spec->n_pids) {
		CLI_ERROR("--pagefault profiles exactly one process: give --pid=N, "
			  "or --comm/--exe/--cgroup/--container_pid rules with "
			  "--first_match (and no --children or --pid)");
		return -EINVAL;
	}
	/* per-session, not secret: never wait for the boot entropy pool */
	if (getrandom(&pf.salt, sizeof(pf.salt), GRND_NONBLOCK) != sizeof(pf.salt))
		pf.salt = mono_ns() ^ ((uint64_t)getpid() << 32);

	pf.markers = false;
	pf.cold_start = spec->mode == CPA_TARGET_DYNAMIC;
	pf.pid = pf.cold_start ? 0 : spec->legacy_pid;
	pf.sample_pages = (uint32_t)pages;
	cfg.enabled = true;
	cfg.sample_pages = pf.sample_pages;
	cfg.salt = pf.salt;
	cfg.release_fn = release_event_cb;
	cfg.stack_lost_fn = stack_records_lost;
	cfg.events_lost_fn = event_records_lost;
	/*
	 * Input is taken from here on: bpf_capture_worker attaches the hooks
	 * and opens the target session right after, and a --first_match
	 * process can exec and fault in its startup before any later worker
	 * runs.
	 */
	pf.tracker = pf_tracker_new();
	if (!pf.tracker) {
		CLI_ERROR("pagefault: out of memory");
		return -ENOMEM;
	}
	pthread_mutex_lock(&pf.lock);
	pf.active = true;
	pthread_mutex_unlock(&pf.lock);
	stack_capture_set_pagefault(&cfg);
	if (pf.cold_start)
		CLI_OUTPUT("pagefault: resident anonymous memory of the first process "
			   "matching %s, from its exec; 1 in %u pages sampled (larger "
			   "pages in proportion), values in bytes", spec->summary, pf.sample_pages);
	else
		CLI_OUTPUT("pagefault: resident anonymous memory of pid %d, 1 in %u "
			   "pages sampled (larger pages in proportion), values in bytes", pf.pid,
			   pf.sample_pages);
	return 0;
}

/* ------------------------------------------------------------ worker -- */

/*
 * After bpf_capture_worker: the hooks are live, so what the target has
 * resident goes to the "before" marker.  A page faulted in since the
 * attach is counted once: by its stack if that was unwound before the
 * scan, else by the marker (the tracker keeps the first record of a live
 * range).  A --first_match target is selected at its exec, with nothing
 * before.
 */
static enum cpa_worker_init_result cpa_pagefault_init(void *cli_ctx, void *worker_ctx)
{
	int ret = 0;

	(void)cli_ctx;
	(void)worker_ctx;
	if (!pf.enabled)
		return CPA_INIT_SKIP;
	pthread_mutex_lock(&pf.lock);
	if (!pf.cold_start)
		ret = charge_resident_locked();
	pthread_mutex_unlock(&pf.lock);
	return ret ? CPA_INIT_FAILED : CPA_INIT_SUCCESS;
}

static void cpa_pagefault_log_stats(void)
{
	struct pf_tracker_stats st;

	pf_tracker_get_stats(pf.tracker, &st);
	CLI_OUTPUT("pagefault: resident=%llu KiB records=%llu stacks=%llu added=%llu "
		   "duplicates=%llu late=%llu late_unknown=%llu lost=%llu "
		   "released=%llu KiB moved=%llu resets=%llu out_of_order=%llu "
		   "failed=%llu unreported=%llu KiB unreported_releases=%llu "
		   "dropped_unseen=%llu",
		   (unsigned long long)(st.resident_bytes / 1024),
		   (unsigned long long)st.records, (unsigned long long)st.stacks,
		   (unsigned long long)st.added, (unsigned long long)st.duplicates,
		   (unsigned long long)st.late, (unsigned long long)st.late_unknown,
		   (unsigned long long)pf.lost,
		   (unsigned long long)(st.released_bytes / 1024),
		   (unsigned long long)st.moved, (unsigned long long)st.resets,
		   (unsigned long long)st.out_of_order, (unsigned long long)st.failed,
		   (unsigned long long)(pf.losses.pages * PF_PAGE_SIZE / 1024),
		   (unsigned long long)pf.losses.releases,
		   (unsigned long long)pf.losses.unseen);
}

/* Stack ids belong to the tracemap, which a runtime restart replaces. */
static void cpa_pagefault_pause(void *worker_ctx)
{
	(void)worker_ctx;
	pthread_mutex_lock(&pf.lock);
	pf.active = false;
	pthread_mutex_unlock(&pf.lock);
}

static void cpa_pagefault_restore(void *worker_ctx)
{
	int ret;

	(void)worker_ctx;
	/* the live set from scratch: its stack ids went with the tracemap */
	pthread_mutex_lock(&pf.lock);
	pf_tracker_clear(pf.tracker);
	pf.markers = false;
	pf.written_sec = UINT64_MAX;	/* a new tracemap */
	ret = charge_resident_locked();
	pf.active = ret == 0;
	pthread_mutex_unlock(&pf.lock);
	if (ret)
		CLI_ERROR("pagefault: cannot restart tracking");
}

static void cpa_pagefault_destroy(void *worker_ctx)
{
	(void)worker_ctx;
	pthread_mutex_lock(&pf.lock);
	pf.active = false;
	if (pf.tracker) {
		pf_tracker_flush(pf.tracker, UINT64_MAX);	/* nothing more comes */
		check_losses_locked();
		cpa_pagefault_log_stats();
		pf_tracker_free(pf.tracker);
		pf.tracker = NULL;
	}
	pthread_mutex_unlock(&pf.lock);
}

struct cpa_worker pagefault_worker = {
	.worker_name = "pagefault_worker",
	.worker_ctx = NULL,
	/* after bpf_capture_worker: the hooks are live before the baseline */
	.worker_index = 11,

	.init_fn = cpa_pagefault_init,
	.destroy_fn = cpa_pagefault_destroy,
	.pause_fn = cpa_pagefault_pause,
	.restore_fn = cpa_pagefault_restore,
	.timer_fn = cpa_pagefault_timer_fn,
	.main_worker_fn = NULL,
};
