// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

/*
 * Shared contract of the resident anonymous-memory profile (cpa monitor
 * --pagefault) between the stack_capture_pagefault BPF variant and the
 * userspace tracker.
 *
 * The BPF side reports two things for the one target process:
 *   - a sampled new anonymous page: a regular stack_event whose pf block
 *     carries the page address, the number of pages it stands for and the
 *     weight to charge (Horvitz-Thompson: pages / sampling probability);
 *   - address-space changes as struct pf_release_event: releases and moves
 *     of successful munmap, madvise, brk shrink, mmap MAP_FIXED and mremap
 *     calls, in whole pages and stamped with the call's entry; exec and
 *     teardown of the address space; and a sampled page whose stack event
 *     did not fit its buffer.
 * The userspace tracker keeps the live set; the BPF side keeps no state
 * about pages.
 */

#ifndef CPA_BPF_PAGEFAULT_SAMPLE_H
#define CPA_BPF_PAGEFAULT_SAMPLE_H

#ifndef __BPF__
#include <stdint.h>
#include <linux/types.h>
#endif

#define PF_PAGE_SHIFT 12
#define PF_PAGE_SIZE (1ULL << PF_PAGE_SHIFT)
/* A PMD-mapped transparent huge page: 2 MiB of 4 KiB pages. */
#define PF_THP_ORDER 9
#define PF_THP_PAGES (1U << PF_THP_ORDER)
#define PF_THP_SIZE (PF_THP_PAGES * PF_PAGE_SIZE)
/* N <= PF_THP_PAGES keeps every THP in the sample with its exact size. */
#define PF_SAMPLE_PAGES_MAX PF_THP_PAGES

/* pf.flags of a stack_event */
#define PF_META_VALID 0x1	/* the event is a sampled new anonymous page */

struct pf_sample_meta {
	__u64 addr;		/* page address, aligned to the pages' size */
	__u32 pages;		/* pages mapped by this fault: a power of two,
				 * 1 to PF_THP_PAGES */
	__u32 weight;		/* pages this sample stands for */
	__u32 flags;
	__u32 pad;
};

enum pf_release_kind {
	PF_RELEASE = 1,		/* [start, end) no longer backed by these pages */
	PF_MOVE = 2,		/* mremap: [start, end) now lives at new_start */
	PF_RESET = 3,		/* exec or exit: the address space is gone */
	PF_DROPPED = 4,		/* sampled pages [start, end) without their stack */
};

struct pf_release_event {
	__u64 ts;		/* bpf_ktime_get_ns() */
	__u64 start;
	__u64 end;
	__u64 new_start;	/* PF_MOVE only */
	__u32 kind;
	__u32 weight;		/* PF_DROPPED only: pages the sample stands for */
};

/* BPF-side configuration (ARRAY map, one entry), written by userspace once. */
struct pf_config {
	__u64 salt;		/* per session: which pages are sampled */
	__u32 tgid;		/* 0: the process target_ctl latched */
	__u32 sample_mask;	/* sample_pages - 1, sample_pages a power of two */
};

/* Written by BPF only: reports that could not be made. */
struct pf_state {
	__u64 lost_pages;	/* sampled pages (weighted) reported nowhere */
	__u64 lost_releases;	/* releases, moves and resets, and syscalls
				 * that could not be followed to their result */
	/* outputs BPF saw fail; the kernel also drops records unseen (a
	 * failed perf output reports no error before 5.4) */
	__u64 failed_stack_outputs;
	__u64 failed_event_outputs;
	__u64 unknown_folios;	/* new pages of a size the judge cannot
				 * believe, not recorded */
};

/* A 64-bit mixer (splitmix64 finalizer): only multiply, shift and xor. */
static inline __attribute__((always_inline)) __u64 pf_mix64(__u64 x)
{
	x ^= x >> 30;
	x *= 0xbf58476d1ce4e5b9ULL;
	x ^= x >> 27;
	x *= 0x94d049bb133111ebULL;
	x ^= x >> 31;
	return x;
}

/*
 * The page each block of N = mask + 1 aligned pages has in the sample: a
 * position the session salt and the block's address pick.  The decision
 * of a page and of any folio over it are then one: whatever size the
 * memory at an address arrives in (a folio, its pages one by one after a
 * split or a copy on write, the /proc/PID/pagemap baseline), it is sampled
 * when it covers that position, so the same memory is never counted once
 * as a folio and again as a page of it.
 */
static inline __attribute__((always_inline)) __u64
pf_block_pick(__u64 page, __u64 salt, __u32 mask)
{
	return pf_mix64((page & ~(__u64)mask) ^ salt) & mask;
}

/*
 * Whether the 4 KiB page at @addr is sampled: each page is with
 * probability 1 / (mask + 1), and always or never in a session.
 */
static inline __attribute__((always_inline)) int
pf_page_sampled(__u64 addr, __u64 salt, __u32 mask)
{
	__u64 page = addr >> PF_PAGE_SHIFT;

	return (page & mask) == pf_block_pick(page, salt, mask);
}

/*
 * pf_page_sampled() for @pages new pages at @addr (a power of two, @addr
 * aligned to their size), N = mask + 1: N pages or more are always
 * sampled, with their own number of pages; fewer when they cover their
 * block's position, with probability pages / N, standing for N.  The
 * expected weight is the size whatever it is.  One page is sampled exactly
 * when pf_page_sampled() says so, a THP always.
 */
static inline __attribute__((always_inline)) int
pf_pages_sampled(__u64 addr, __u32 pages, __u64 salt, __u32 mask)
{
	__u64 page = addr >> PF_PAGE_SHIFT;

	if (pages > mask)
		return 1;
	return (((page ^ pf_block_pick(page, salt, mask)) & mask) &
		~(__u64)(pages - 1)) == 0;
}

/* The pages a sample of pf_pages_sampled() stands for. */
static inline __attribute__((always_inline)) __u32
pf_pages_weight(__u32 pages, __u32 mask)
{
	return pages > mask ? pages : mask + 1;
}

#endif
