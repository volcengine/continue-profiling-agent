// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

/*
 * Unit tests of the cpa monitor --pagefault live-set tracker and of the page
 * sampling it relies on.  The tracker is pure: no BPF, no /proc.
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <cpa_bpf/pagefault_sample.h>
#include "cpa_pagefault_tracker.h"

#define KIB 1024ULL
#define MIB (1024ULL * KIB)
#define PAGE PF_PAGE_SIZE
#define THP PF_THP_SIZE
#define ALL (~0ULL)

static int failures;

#define CHECK(cond, name) do { \
	bool ok_ = (cond); \
	printf("%s %s\n", ok_ ? "PASS" : "FAIL", name); \
	failures += !ok_; \
} while (0)

struct sum { uint32_t stack; uint64_t bytes; };

static void add_stack(uint32_t stack, uint64_t bytes, void *arg)
{
	struct sum *s = arg;

	if (stack == s->stack)
		s->bytes += bytes;
}

static uint64_t stack_bytes(struct pf_tracker *t, uint32_t stack)
{
	struct sum s = { stack, 0 };

	pf_tracker_for_each_stack(t, add_stack, &s);
	return s.bytes;
}

static struct pf_tracker_stats stats(struct pf_tracker *t)
{
	struct pf_tracker_stats st;

	pf_tracker_get_stats(t, &st);
	return st;
}

static uint64_t resident(struct pf_tracker *t)
{
	return stats(t).resident_bytes;
}

/* Applied at once, in the order given. */
static void release(struct pf_tracker *t, uint64_t ts, uint64_t start, uint64_t end)
{
	pf_tracker_submit(t, PF_EV_RELEASE, ts, start, end, 0);
	pf_tracker_flush(t, ALL);
}

static void move(struct pf_tracker *t, uint64_t ts, uint64_t start, uint64_t end,
		 uint64_t to)
{
	pf_tracker_submit(t, PF_EV_MOVE, ts, start, end, to);
	pf_tracker_flush(t, ALL);
}

static void reset(struct pf_tracker *t, uint64_t ts)
{
	pf_tracker_submit(t, PF_EV_RESET, ts, 0, 0, 0);
	pf_tracker_flush(t, ALL);
}

/* 4 KiB samples of weight 16 at every page of [start, end) */
static void alloc_range(struct pf_tracker *t, uint64_t ts, uint64_t start,
			uint64_t end, uint32_t stack)
{
	for (uint64_t a = start; a < end; a += PAGE)
		pf_tracker_alloc(t, ts, a, 1, 16 * PAGE, stack);
}

static void basics(void)
{
	struct pf_tracker *t = pf_tracker_new();

	alloc_range(t, 10, 0x10000000, 0x10000000 + 64 * PAGE, 1);
	alloc_range(t, 10, 0x20000000, 0x20000000 + 32 * PAGE, 2);
	CHECK(stack_bytes(t, 1) == 64 * 16 * PAGE && stack_bytes(t, 2) == 32 * 16 * PAGE,
	      "allocations are charged to their stack");
	/* inside the reorder window an older release could still come */
	CHECK(pf_tracker_alloc(t, 11, 0x10000000, 1, 16 * PAGE, 3) == PF_ALLOC_QUEUED,
	      "a page landing on a live one waits for the reorder window");
	pf_tracker_flush(t, 12);
	CHECK(stats(t).duplicates == 1 && stack_bytes(t, 3) == 0,
	      "a live page faulting again keeps its first stack (swap-in, CoW)");
	release(t, 20, 0x10000000, 0x10000000 + 16 * PAGE);
	CHECK(stack_bytes(t, 1) == 48 * 16 * PAGE, "munmap removes exactly its pages");
	CHECK(pf_tracker_alloc(t, 25, 0x10000000, 1, 16 * PAGE, 3) == PF_ALLOC_ADDED,
	      "a released page faulting in again is new memory");
	release(t, 30, 0, ALL);
	CHECK(resident(t) == 0, "a huge range walks the buckets, not the address space");
	pf_tracker_free(t);
}

static void thp(void)
{
	struct pf_tracker *t = pf_tracker_new();
	const uint64_t a = 0x40000000;

	pf_tracker_alloc(t, 10, a, PF_THP_PAGES, THP, 7);
	CHECK(stack_bytes(t, 7) == THP, "a THP is charged its exact size");
	release(t, 20, a + 512 * KIB, a + 1536 * KIB);
	CHECK(stack_bytes(t, 7) == THP - MIB, "a partial munmap of a THP removes its bytes");
	release(t, 21, a + 512 * KIB, a + 1536 * KIB);
	CHECK(stack_bytes(t, 7) == THP - MIB,
	      "releasing the same part again removes nothing more");
	CHECK(pf_tracker_alloc(t, 22, a + 512 * KIB, 1, PAGE, 8) == PF_ALLOC_ADDED,
	      "a page faulting into the hole of a THP is new memory");
	release(t, 30, a, a + THP);
	CHECK(resident(t) == 0, "the rest goes with the rest of the range");
	pf_tracker_free(t);

	/* half released before the THP's own allocation arrives */
	t = pf_tracker_new();
	release(t, 20, a, a + MIB);
	pf_tracker_alloc(t, 10, a, PF_THP_PAGES, THP, 7);
	CHECK(resident(t) == MIB, "a late THP keeps what the release left of it");
	pf_tracker_free(t);

	/* the first page of a THP released, then faulted in again */
	t = pf_tracker_new();
	pf_tracker_alloc(t, 10, a, PF_THP_PAGES, THP, 7);
	release(t, 20, a, a + PAGE);
	CHECK(pf_tracker_alloc(t, 30, a, 1, PAGE, 8) == PF_ALLOC_ADDED &&
	      resident(t) == THP, "a released first page of a THP faults in anew");
	pf_tracker_free(t);

	/* half moved away, then both places released */
	t = pf_tracker_new();
	pf_tracker_alloc(t, 10, a, PF_THP_PAGES, THP, 7);
	move(t, 20, a + MIB, a + THP, 0x50000000 + 3 * PAGE);
	CHECK(resident(t) == THP, "a moved part of a THP keeps its bytes");
	release(t, 30, a, a + MIB);
	release(t, 31, 0x50000000 + 3 * PAGE, 0x50000000 + 3 * PAGE + MIB);
	CHECK(resident(t) == 0,
	      "both parts are released where they are (across 2 MiB regions)");
	pf_tracker_free(t);
}

/* Inputs in the order they may reach the tracker. */
static void ordering(void)
{
	struct pf_tracker *t = pf_tracker_new();
	const uint64_t A = 0x30000000, B = 0x31000000, C = 0x32000000;

	/* the release reaches the tracker before the allocation it frees */
	release(t, 50, A, A + 8 * PAGE);
	CHECK(pf_tracker_alloc(t, 40, A, 1, PAGE, 1) == PF_ALLOC_LATE &&
	      resident(t) == 0, "an allocation older than its release is dropped");
	CHECK(pf_tracker_alloc(t, 60, A, 1, PAGE, 1) == PF_ALLOC_ADDED,
	      "a later allocation at the same address is new memory");
	pf_tracker_free(t);

	/* per-CPU buffers: releases in any order within the flush window */
	t = pf_tracker_new();
	pf_tracker_submit(t, PF_EV_RELEASE, 30, A, A + PAGE, 0);
	pf_tracker_submit(t, PF_EV_RELEASE, 10, B, B + PAGE, 0);
	pf_tracker_flush(t, 100);
	pf_tracker_alloc(t, 20, A, 1, PAGE, 1);
	CHECK(resident(t) == 0, "a late allocation meets a newer release logged "
	      "before an older one");
	pf_tracker_free(t);

	/* moved before its stack was unwound */
	t = pf_tracker_new();
	move(t, 20, A, A + PAGE, B);
	pf_tracker_alloc(t, 10, A, 1, PAGE, 1);
	CHECK(resident(t) == PAGE && stack_bytes(t, 1) == PAGE,
	      "a late allocation follows the move of its page");
	release(t, 30, B, B + PAGE);
	CHECK(resident(t) == 0, "and is released at its new address");
	pf_tracker_free(t);

	/* a move and a newer release of its target, submitted swapped */
	t = pf_tracker_new();
	pf_tracker_alloc(t, 10, A, 1, PAGE, 1);
	pf_tracker_submit(t, PF_EV_RELEASE, 30, B, B + PAGE, 0);
	pf_tracker_submit(t, PF_EV_MOVE, 20, A, A + PAGE, B);
	pf_tracker_flush(t, 100);
	CHECK(resident(t) == 0, "events are applied in time order, not arrival order");
	pf_tracker_free(t);

	/* exec: a page of the new address space arrives before the reset */
	t = pf_tracker_new();
	pf_tracker_alloc(t, 10, A, 1, PAGE, 1);
	pf_tracker_alloc(t, 30, B, 1, PAGE, 2);
	reset(t, 20);
	CHECK(stack_bytes(t, 1) == 0 && stack_bytes(t, 2) == PAGE,
	      "a reset takes the old address space, not the new one");
	CHECK(pf_tracker_alloc(t, 15, A + PAGE, 1, PAGE, 1) == PF_ALLOC_LATE,
	      "allocations of the old address space arriving late are dropped");
	pf_tracker_free(t);

	/* munmap, mmap of the same addresses and a fault, all before the
	 * release is applied: the new page is not the released one */
	t = pf_tracker_new();
	pf_tracker_alloc(t, 10, A, 1, PAGE, 1);
	pf_tracker_flush(t, 15);
	pf_tracker_submit(t, PF_EV_RELEASE, 20, A, A + PAGE, 0);
	CHECK(pf_tracker_alloc(t, 30, A, 1, PAGE, 2) == PF_ALLOC_QUEUED,
	      "an allocation newer than a queued release waits behind it");
	pf_tracker_flush(t, 100);
	CHECK(resident(t) == PAGE && stack_bytes(t, 1) == 0 &&
	      stack_bytes(t, 2) == PAGE && stats(t).duplicates == 0,
	      "a page refaulted after its release counts, with its own stack");
	/* the same when a move emptied it (MREMAP_DONTUNMAP) */
	pf_tracker_submit(t, PF_EV_MOVE, 40, A, A + PAGE, B);
	pf_tracker_alloc(t, 50, A, 1, PAGE, 3);
	pf_tracker_flush(t, 100);
	CHECK(resident(t) == 2 * PAGE && stack_bytes(t, 2) == PAGE &&
	      stack_bytes(t, 3) == PAGE,
	      "a range emptied by a move and refaulted holds both");
	/* clearing the live set drops queued allocations, keeps events */
	pf_tracker_submit(t, PF_EV_RELEASE, 60, B, B + PAGE, 0);
	pf_tracker_alloc(t, 70, C, 1, PAGE, 4);
	pf_tracker_clear(t);
	pf_tracker_flush(t, 100);
	CHECK(resident(t) == 0 && stack_bytes(t, 4) == 0,
	      "a cleared live set forgets its queued allocations");
	pf_tracker_free(t);

	/* the refault's report first, the older release from another CPU's
	 * buffer after it, both inside the reorder window */
	t = pf_tracker_new();
	pf_tracker_alloc(t, 35, B, 1, PAGE, 5);
	CHECK(pf_tracker_alloc(t, 37, B, 1, PAGE, 6) == PF_ALLOC_QUEUED,
	      "a page landing on a live one inside the window waits");
	pf_tracker_submit(t, PF_EV_RELEASE, 36, B, B + PAGE, 0);
	pf_tracker_flush(t, 38);
	CHECK(resident(t) == PAGE && stack_bytes(t, 5) == 0 &&
	      stack_bytes(t, 6) == PAGE,
	      "and is placed after a release that reached the tracker later");
	pf_tracker_free(t);

	/* an event older than an earlier flush bound: applied, counted */
	t = pf_tracker_new();
	pf_tracker_alloc(t, 10, A, 1, PAGE, 1);
	pf_tracker_flush(t, 100);
	pf_tracker_submit(t, PF_EV_RELEASE, 50, A, A + PAGE, 0);
	CHECK(resident(t) == 0 && stats(t).out_of_order == 1,
	      "an event older than the flush bound is applied and counted");
	pf_tracker_free(t);

	/* allocations older than the log reaches back */
	t = pf_tracker_new();
	for (uint64_t i = 0; i < 5000; i++)
		release(t, 100 + i, 0x70000000 + i * PAGE, 0x70000000 + (i + 1) * PAGE);
	pf_tracker_alloc(t, 50, 0x60000000, 1, PAGE, 1);
	CHECK(stats(t).late_unknown == 1, "an allocation older than the log is counted");
	pf_tracker_free(t);
}

static void moves(void)
{
	struct pf_tracker *t = pf_tracker_new();

	alloc_range(t, 10, 0x60000000, 0x60000000 + 16 * PAGE, 5);
	move(t, 20, 0x60000000, 0x60000000 + 16 * PAGE, 0x70000000);
	CHECK(stack_bytes(t, 5) == 16 * 16 * PAGE, "mremap keeps the pages and their stack");
	release(t, 25, 0x60000000, 0x60000000 + 16 * PAGE);
	CHECK(stack_bytes(t, 5) == 16 * 16 * PAGE, "the old range holds nothing any more");
	release(t, 30, 0x70000000, 0x70000000 + 16 * PAGE);
	CHECK(stack_bytes(t, 5) == 0, "moved pages are released at their new address");
	pf_tracker_free(t);

	/* MREMAP_FIXED onto two live pages, growing to two pages */
	t = pf_tracker_new();
	pf_tracker_alloc(t, 5, 0x80000000, 1, PAGE, 1);
	pf_tracker_alloc(t, 5, 0x90000000, 1, PAGE, 2);
	pf_tracker_alloc(t, 5, 0x90000000 + PAGE, 1, PAGE, 2);
	release(t, 10, 0x90000000, 0x90000000 + 2 * PAGE);	/* the target range */
	move(t, 11, 0x80000000, 0x80000000 + PAGE, 0x90000000);
	CHECK(resident(t) == PAGE && stack_bytes(t, 1) == PAGE,
	      "MREMAP_FIXED replaces what was at the target");
	pf_tracker_free(t);
}

/* Each page is in the sample with probability 1/N, whatever the salt. */
static void sampling(void)
{
	const uint32_t n = 16;
	uint64_t hits = 0, pages = 1 << 20;
	double worst = 0;

	for (uint64_t i = 1; i <= 32; i++) {
		uint64_t salt = pf_mix64(i), h = 0;

		for (uint64_t p = 0; p < pages; p++)
			h += pf_page_sampled(0x7f0000000000ULL + p * PAGE, salt, n - 1);
		hits += h;
		double rel = fabs((double)h * n / pages - 1.0);
		if (rel > worst)
			worst = rel;
	}
	CHECK(fabs((double)hits * n / (32.0 * pages) - 1.0) < 0.002,
	      "sampled fraction is 1/N over salts");
	CHECK(worst < 0.02, "every salt samples close to 1/N");

	/*
	 * Horvitz-Thompson: the weighted sample of a region averages to its
	 * true size, over salts.
	 */
	double mean = 0;
	const uint64_t region = 4096;	/* pages: 16 MiB */

	/* session salts are random 64-bit values */
	for (uint64_t i = 1; i <= 256; i++) {
		uint64_t salt = pf_mix64(i), est = 0;

		for (uint64_t p = 0; p < region; p++)
			if (pf_page_sampled(0x555500000000ULL + p * PAGE, salt, n - 1))
				est += n;
		mean += (double)est / 256.0;
	}
	printf("INFO mean estimate %.4f of the true size\n", mean / region);
	CHECK(fabs(mean / region - 1.0) < 0.01, "estimated size is unbiased");
}

/*
 * pf_pages_sampled() of any folio size: one page and a THP decide exactly
 * as before it existed (pf_page_sampled(), always), and a folio smaller
 * than N stands for N pages with probability pages / N.
 */
static void folio_sampling(void)
{
	bool same = true, thp_always = true, sizes_unbiased = true;
	const uint32_t ns[] = { 1, 2, 16, 64, 512 };

	for (uint32_t k = 0; k < sizeof(ns) / sizeof(ns[0]); k++) {
		uint32_t mask = ns[k] - 1;

		for (uint64_t i = 1; i <= 8; i++) {
			uint64_t salt = pf_mix64(i * 7919);

			for (uint64_t p = 0; p < 65536; p++) {
				uint64_t addr = 0x7f1200000000ULL + p * PAGE;

				if (pf_pages_sampled(addr, 1, salt, mask) !=
				    pf_page_sampled(addr, salt, mask) ||
				    pf_pages_weight(1, mask) != mask + 1)
					same = false;
			}
			for (uint64_t p = 0; p < 4096; p++)
				if (!pf_pages_sampled(0x7f1200000000ULL + p * THP,
						      PF_THP_PAGES, salt, mask) ||
				    pf_pages_weight(PF_THP_PAGES, mask) != PF_THP_PAGES)
					thp_always = false;
		}
	}
	CHECK(same, "one page: pf_pages_sampled() is pf_page_sampled(), weight N");
	CHECK(thp_always, "a THP: always sampled, weight 512, for every N");

	/* 16 KiB, 64 KiB and 256 KiB folios at N = 16, 64, 256 */
	for (uint32_t order = 2; order <= 6; order += 2) {
		uint32_t pages = 1U << order;

		for (uint32_t n = 16; n <= 256; n *= 4) {
			uint64_t region = 1 << 16, est = 0, size = 0;	/* pages */

			for (uint64_t i = 1; i <= 64; i++) {
				uint64_t salt = pf_mix64(i * 104729);

				for (uint64_t p = 0; p < region; p += pages) {
					uint64_t addr = 0x7f3400000000ULL + p * PAGE;

					if (pf_pages_sampled(addr, pages, salt, n - 1))
						est += pf_pages_weight(pages, n - 1);
					size += pages;
				}
			}
			double rel = (double)est / size;

			printf("INFO %u-page folios at N=%u: estimate %.4f of the "
			       "true size\n", pages, n, rel);
			if (fabs(rel - 1.0) > 0.03 ||
			    (pages >= n && est != size))
				sizes_unbiased = false;
		}
	}
	CHECK(sizes_unbiased, "folios of any size: unbiased, exact once >= N");

	/*
	 * A folio and the pages of it agree: a sampled folio has exactly one
	 * page sampled on its own, an unsampled one none (a copy on write or
	 * the pagemap baseline cannot count its memory a second time).
	 */
	bool agree = true;

	for (uint32_t order = 1; order <= 6; order++) {
		uint32_t pages = 1U << order;

		for (uint32_t n = 2; n <= 256; n *= 2) {
			for (uint64_t i = 1; i <= 4; i++) {
				uint64_t salt = pf_mix64(i * 15485863);

				for (uint64_t p = 0; p < 8192; p += pages) {
					uint64_t addr = 0x7f5600000000ULL + p * PAGE;
					int folio = pf_pages_sampled(addr, pages, salt, n - 1);
					uint32_t alone = 0;

					for (uint32_t j = 0; j < pages; j++)
						alone += pf_page_sampled(addr + j * PAGE,
									 salt, n - 1);
					if (pages >= n ? alone != pages / n :
							 alone != (uint32_t)folio)
						agree = false;
				}
			}
		}
	}
	CHECK(agree, "a folio and its pages are sampled alike");
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	basics();
	thp();
	ordering();
	moves();
	sampling();
	folio_sampling();
	printf("failures=%d\n", failures);
	return failures ? 1 : 0;
}
