// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "cpa_pagefault_tracker.h"

#include <stdlib.h>
#include <string.h>

#include <cpa_bpf/pagefault_sample.h>
#include "uthash.h"

/* Records are grouped by 2 MiB region, the THP size; none spans two. */
#define PF_BUCKET_SHIFT 21
#define PF_BUCKET_SIZE (1ULL << PF_BUCKET_SHIFT)
/* Applied events remembered for allocations that arrive after them. */
#define PF_EVENT_LOG 4096

struct pf_rec {
	uint64_t addr;
	uint64_t len;
	uint64_t bytes;		/* resident bytes this range stands for */
	uint64_t ts;		/* at this address since */
	uint32_t stack;
};

/* A growable array of records. */
struct pf_recs {
	struct pf_rec *v;
	uint32_t n, cap;
};

/* The records of one 2 MiB region, sorted by address, disjoint. */
struct pf_bucket {
	uint64_t key;
	struct pf_recs recs;
	UT_hash_handle hh;
};

struct pf_stack {
	uint32_t stack;
	uint64_t bytes;
	UT_hash_handle hh;
};

struct pf_event {
	uint64_t ts, start, end, new_start;
	uint32_t kind;
	uint32_t stack;		/* PF_EV_ALLOC */
	uint64_t bytes;		/* PF_EV_ALLOC */
};

/* An allocation queued behind older events (pending only, never logged). */
#define PF_EV_ALLOC 0x100

/* Events sorted by time: a ring when bounded (the log). */
struct pf_events {
	struct pf_event *v;
	uint32_t head, n, cap;
};

struct pf_tracker {
	struct pf_bucket *buckets;
	struct pf_stack *stacks;
	struct pf_events pending;	/* submitted, not applied yet */
	struct pf_events log;		/* applied, most recent PF_EVENT_LOG */
	uint64_t flushed;		/* bound of the last flush */
	uint64_t forgotten;		/* newest event dropped from the log */
	uint64_t reset_ts;		/* newest reset applied */
	struct pf_tracker_stats stats;
};

/* ------------------------------------------------------------ records -- */

static uint64_t rec_end(const struct pf_rec *r)
{
	return r->addr + r->len;
}

/* The part [lo, hi) of @r, with its share of the bytes (shares add up). */
static struct pf_rec rec_part(const struct pf_rec *r, uint64_t lo, uint64_t hi)
{
	struct pf_rec p = *r;
	unsigned __int128 b = r->bytes;

	p.addr = lo;
	p.len = hi - lo;
	p.bytes = (uint64_t)(b * (hi - r->addr) / r->len -
			     b * (lo - r->addr) / r->len);
	return p;
}

/* Room for @extra more records; the pushes that follow cannot fail. */
static bool recs_reserve(struct pf_tracker *t, struct pf_recs *a, uint32_t extra)
{
	uint32_t cap = a->cap ? a->cap : 4;
	struct pf_rec *v;

	while (cap < a->n + extra)
		cap *= 2;
	if (cap == a->cap)
		return true;
	v = realloc(a->v, cap * sizeof(*v));
	if (!v) {
		t->stats.failed++;
		return false;
	}
	a->v = v;
	a->cap = cap;
	return true;
}

static void recs_push(struct pf_recs *a, const struct pf_rec *r)
{
	a->v[a->n++] = *r;
}

static void stack_add(struct pf_tracker *t, uint32_t stack, int64_t delta)
{
	struct pf_stack *s = NULL;

	if (!delta)
		return;
	HASH_FIND(hh, t->stacks, &stack, sizeof(stack), s);
	if (!s) {
		if (delta < 0)
			return;
		s = calloc(1, sizeof(*s));
		if (!s) {
			t->stats.failed++;
			return;
		}
		s->stack = stack;
		HASH_ADD(hh, t->stacks, stack, sizeof(s->stack), s);
	}
	s->bytes += delta;
	t->stats.resident_bytes += delta;
	if (!s->bytes) {
		HASH_DEL(t->stacks, s);
		free(s);
	}
}

static struct pf_bucket *bucket_find(struct pf_tracker *t, uint64_t key)
{
	struct pf_bucket *b = NULL;

	HASH_FIND(hh, t->buckets, &key, sizeof(key), b);
	return b;
}

static void bucket_drop(struct pf_tracker *t, struct pf_bucket *b)
{
	HASH_DEL(t->buckets, b);
	free(b->recs.v);
	free(b);
}

/*
 * Add the parts of @r (within one bucket) no record covers yet: a range
 * that is live already keeps its first stack.  Returns the bytes added.
 */
static uint64_t bucket_insert(struct pf_tracker *t, const struct pf_rec *r)
{
	uint64_t key = r->addr >> PF_BUCKET_SHIFT, at = r->addr, added = 0;
	struct pf_bucket *b = bucket_find(t, key);
	struct pf_recs out = { 0 };

	if (!b) {
		b = calloc(1, sizeof(*b));
		if (!b) {
			t->stats.failed++;
			return 0;
		}
		b->key = key;
		HASH_ADD(hh, t->buckets, key, sizeof(b->key), b);
	}
	/* the existing records, and a gap of @r before each and at the end */
	if (!recs_reserve(t, &out, 2 * b->recs.n + 1)) {
		if (!b->recs.n)
			bucket_drop(t, b);
		return 0;
	}
	for (uint32_t i = 0; i <= b->recs.n; i++) {
		const struct pf_rec *e = i < b->recs.n ? &b->recs.v[i] : NULL;
		uint64_t gap_end = e && e->addr < rec_end(r) ? e->addr : rec_end(r);

		if (at < gap_end) {
			struct pf_rec part = rec_part(r, at, gap_end);

			recs_push(&out, &part);
			added += part.bytes;
			stack_add(t, part.stack, (int64_t)part.bytes);
			t->stats.records++;
		}
		if (!e)
			break;
		if (rec_end(e) > at)
			at = rec_end(e);
		recs_push(&out, e);
	}
	free(b->recs.v);
	b->recs = out;
	if (!b->recs.n)
		bucket_drop(t, b);
	return added;
}

/* Whether a record covers part of [start, end). */
static bool range_live(struct pf_tracker *t, uint64_t start, uint64_t end)
{
	for (uint64_t key = start >> PF_BUCKET_SHIFT;
	     key <= (end - 1) >> PF_BUCKET_SHIFT; key++) {
		struct pf_bucket *b = bucket_find(t, key);

		for (uint32_t i = 0; b && i < b->recs.n; i++)
			if (b->recs.v[i].addr < end && rec_end(&b->recs.v[i]) > start)
				return true;
	}
	return false;
}

/* Add @r, split at bucket boundaries.  Returns the bytes added. */
static uint64_t insert_rec(struct pf_tracker *t, const struct pf_rec *r)
{
	uint64_t added = 0;

	for (uint64_t lo = r->addr; lo < rec_end(r);) {
		uint64_t hi = (lo | (PF_BUCKET_SIZE - 1)) + 1;
		struct pf_rec part;

		if (hi > rec_end(r))
			hi = rec_end(r);
		part = rec_part(r, lo, hi);
		added += bucket_insert(t, &part);
		lo = hi;
	}
	return added;
}

/*
 * Apply @ev to @in: parts of records that were in its range before it
 * are released (dropped) or moved (to @moved, re-addressed).  The rest
 * goes to @keep.  Returns the bytes taken out.  The range is inside at
 * most one record, so @keep needs room for in->n + 1, @moved for in->n.
 */
static uint64_t apply_to_recs(const struct pf_event *ev, const struct pf_recs *in,
			      struct pf_recs *keep, struct pf_recs *moved)
{
	uint64_t taken = 0;

	for (uint32_t i = 0; i < in->n; i++) {
		const struct pf_rec *r = &in->v[i];
		uint64_t lo = r->addr > ev->start ? r->addr : ev->start;
		uint64_t hi = rec_end(r) < ev->end ? rec_end(r) : ev->end;
		struct pf_rec part;

		if (ev->kind == PF_EV_RESET && r->ts < ev->ts) {
			taken += r->bytes;
			continue;
		}
		if (ev->kind == PF_EV_RESET || r->ts >= ev->ts || lo >= hi) {
			recs_push(keep, r);
			continue;
		}
		if (r->addr < lo) {
			part = rec_part(r, r->addr, lo);
			recs_push(keep, &part);
		}
		part = rec_part(r, lo, hi);
		taken += part.bytes;
		if (ev->kind == PF_EV_MOVE) {
			part.addr = part.addr - ev->start + ev->new_start;
			part.ts = ev->ts;
			recs_push(moved, &part);
		}
		if (hi < rec_end(r)) {
			part = rec_part(r, hi, rec_end(r));
			recs_push(keep, &part);
		}
	}
	return taken;
}

/* Apply @ev to the live set of bucket @b; moved parts go to @moved. */
static void apply_to_bucket(struct pf_tracker *t, struct pf_bucket *b,
			    const struct pf_event *ev, struct pf_recs *moved)
{
	struct pf_recs keep = { 0 };
	uint32_t before = b->recs.n, moved_before = moved ? moved->n : 0;
	uint64_t taken;

	/* out of memory: this bucket misses the event (counted as failed) */
	if (!recs_reserve(t, &keep, b->recs.n + 1) ||
	    (moved && !recs_reserve(t, moved, b->recs.n))) {
		free(keep.v);
		return;
	}
	taken = apply_to_recs(ev, &b->recs, &keep, moved);
	/* per-stack sums: what left, what stays split */
	for (uint32_t i = 0; i < b->recs.n; i++)
		stack_add(t, b->recs.v[i].stack, -(int64_t)b->recs.v[i].bytes);
	for (uint32_t i = 0; i < keep.n; i++)
		stack_add(t, keep.v[i].stack, (int64_t)keep.v[i].bytes);
	t->stats.records += keep.n;
	t->stats.records -= before;
	if (ev->kind == PF_EV_MOVE)
		t->stats.moved += moved->n - moved_before;
	else
		t->stats.released_bytes += taken;
	free(b->recs.v);
	b->recs = keep;
	if (!b->recs.n)
		bucket_drop(t, b);
}

/* Apply @ev to the live set. */
static void apply_event(struct pf_tracker *t, const struct pf_event *ev)
{
	struct pf_recs moved = { 0 };
	struct pf_bucket *b, *tmp;

	if (ev->kind == PF_EV_RESET) {
		HASH_ITER(hh, t->buckets, b, tmp)
			apply_to_bucket(t, b, ev, NULL);
		if (ev->ts > t->reset_ts)
			t->reset_ts = ev->ts;
		t->stats.resets++;
		return;
	}
	if (ev->end <= ev->start)
		return;
	uint64_t first = ev->start >> PF_BUCKET_SHIFT;
	uint64_t last = (ev->end - 1) >> PF_BUCKET_SHIFT;

	/* a huge munmap of mostly empty address space: walk the buckets */
	if (last - first >= HASH_COUNT(t->buckets)) {
		HASH_ITER(hh, t->buckets, b, tmp)
			if (b->key >= first && b->key <= last)
				apply_to_bucket(t, b, ev, &moved);
	} else {
		for (uint64_t key = first; key <= last; key++) {
			b = bucket_find(t, key);
			if (b)
				apply_to_bucket(t, b, ev, &moved);
		}
	}
	for (uint32_t i = 0; i < moved.n; i++)
		insert_rec(t, &moved.v[i]);
	free(moved.v);
}

/* ------------------------------------------------------------- events -- */

static struct pf_event *ev_at(const struct pf_events *q, uint32_t i)
{
	return &q->v[(q->head + i) % q->cap];
}

/* Index of the first event newer than @ts. */
static uint32_t ev_after(const struct pf_events *q, uint64_t ts)
{
	uint32_t lo = 0, hi = q->n;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2;

		if (ev_at(q, mid)->ts <= ts)
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo;
}

/*
 * Insert @ev in time order; they come nearly sorted, so the shift is
 * short.  A bounded queue (the log) drops its oldest when full.
 */
static void ev_insert(struct pf_tracker *t, struct pf_events *q,
		      const struct pf_event *ev, uint32_t bound)
{
	uint32_t at;

	if (q->n == q->cap) {
		if (bound && q->cap >= bound) {
			if (ev_at(q, 0)->ts > t->forgotten)
				t->forgotten = ev_at(q, 0)->ts;
			q->head = (q->head + 1) % q->cap;
			q->n--;
		} else {
			uint32_t cap = q->cap ? q->cap * 2 : 64;
			struct pf_event *v = malloc(cap * sizeof(*v));

			if (!v) {
				t->stats.failed++;
				return;
			}
			for (uint32_t i = 0; i < q->n; i++)
				v[i] = *ev_at(q, i);
			free(q->v);
			q->v = v;
			q->cap = cap;
			q->head = 0;
		}
	}
	at = ev_after(q, ev->ts);
	for (uint32_t i = q->n; i > at; i--)
		*ev_at(q, i) = *ev_at(q, i - 1);
	*ev_at(q, at) = *ev;
	q->n++;
}

static void log_and_apply(struct pf_tracker *t, const struct pf_event *ev)
{
	apply_event(t, ev);
	ev_insert(t, &t->log, ev, PF_EVENT_LOG);
}

/* @rec where the logged events newer than it left it. */
static enum pf_alloc_result place_alloc(struct pf_tracker *t,
					const struct pf_rec *rec)
{
	struct pf_recs pieces = { 0 };
	uint64_t added = 0;
	uint32_t i;

	if (rec->ts < t->reset_ts) {
		t->stats.late++;
		return PF_ALLOC_LATE;
	}
	if (rec->ts < t->forgotten)
		t->stats.late_unknown++;	/* events it missed are gone */
	if (!recs_reserve(t, &pieces, 1))
		return PF_ALLOC_LATE;
	recs_push(&pieces, rec);
	/* where the events since its fault left it */
	for (i = ev_after(&t->log, rec->ts); i < t->log.n && pieces.n; i++) {
		struct pf_recs keep = { 0 };

		/* kept and moved parts both go on */
		if (!recs_reserve(t, &keep, 2 * pieces.n + 1))
			break;
		apply_to_recs(ev_at(&t->log, i), &pieces, &keep, &keep);
		free(pieces.v);
		pieces = keep;
	}
	for (i = 0; i < pieces.n; i++)
		added += insert_rec(t, &pieces.v[i]);
	free(pieces.v);
	if (!added && !pieces.n) {
		t->stats.late++;
		return PF_ALLOC_LATE;
	}
	if (!added) {
		t->stats.duplicates++;
		return PF_ALLOC_DUPLICATE;
	}
	t->stats.added++;
	return PF_ALLOC_ADDED;
}

static enum pf_alloc_result place_queued(struct pf_tracker *t,
					 const struct pf_event *ev)
{
	struct pf_rec rec = {
		.addr = ev->start, .len = ev->end - ev->start,
		.bytes = ev->bytes, .ts = ev->ts, .stack = ev->stack,
	};

	return place_alloc(t, &rec);
}

void pf_tracker_submit(struct pf_tracker *t, enum pf_event_kind kind,
		       uint64_t ts, uint64_t start, uint64_t end,
		       uint64_t new_start)
{
	struct pf_event ev = {
		.ts = ts, .start = start, .end = end, .new_start = new_start,
		.kind = kind,
	};

	if (ts < t->flushed) {
		/* allocations placed since may have missed it */
		t->stats.out_of_order++;
		log_and_apply(t, &ev);
		return;
	}
	ev_insert(t, &t->pending, &ev, 0);
}

void pf_tracker_flush(struct pf_tracker *t, uint64_t bound)
{
	while (t->pending.n && ev_at(&t->pending, 0)->ts < bound) {
		struct pf_event ev = *ev_at(&t->pending, 0);

		t->pending.head = (t->pending.head + 1) % t->pending.cap;
		t->pending.n--;
		if (ev.kind == PF_EV_ALLOC)
			place_queued(t, &ev);
		else
			log_and_apply(t, &ev);
	}
	if (bound > t->flushed)
		t->flushed = bound;
}

enum pf_alloc_result pf_tracker_alloc(struct pf_tracker *t, uint64_t ts,
				      uint64_t addr, uint32_t pages,
				      uint64_t bytes, uint32_t stack)
{
	struct pf_event ev = {
		.ts = ts, .start = addr,
		.end = addr + (uint64_t)pages * PF_PAGE_SIZE,
		.kind = PF_EV_ALLOC, .stack = stack, .bytes = bytes,
	};

	/*
	 * Inside the reorder window an older event may still be queued, or
	 * still in another CPU's buffer: one that releases or moves records
	 * where it lands (munmap, mmap of the same addresses and a fault).
	 * Landing on live records, or behind a queued event, it waits to be
	 * placed in time order; elsewhere nothing can make it a duplicate.
	 */
	if (ts >= t->flushed &&
	    ((t->pending.n && ev_at(&t->pending, 0)->ts < ts) ||
	     range_live(t, ev.start, ev.end))) {
		ev_insert(t, &t->pending, &ev, 0);
		return PF_ALLOC_QUEUED;
	}
	return place_queued(t, &ev);
}

/* ---------------------------------------------------------- lifecycle -- */

struct pf_tracker *pf_tracker_new(void)
{
	return calloc(1, sizeof(struct pf_tracker));
}

void pf_tracker_clear(struct pf_tracker *t)
{
	struct pf_bucket *b, *btmp;
	struct pf_stack *s, *stmp;

	HASH_ITER(hh, t->buckets, b, btmp)
		bucket_drop(t, b);
	HASH_ITER(hh, t->stacks, s, stmp) {
		HASH_DEL(t->stacks, s);
		free(s);
	}
	t->stats.records = 0;
	t->stats.resident_bytes = 0;
	/* queued allocations name stacks of the live set just dropped */
	for (uint32_t i = 0, n = t->pending.n; i < n; i++) {
		struct pf_event ev = *ev_at(&t->pending, 0);

		t->pending.head = (t->pending.head + 1) % t->pending.cap;
		t->pending.n--;
		if (ev.kind != PF_EV_ALLOC)
			*ev_at(&t->pending, t->pending.n++) = ev;
	}
}

void pf_tracker_free(struct pf_tracker *t)
{
	if (!t)
		return;
	pf_tracker_clear(t);
	free(t->pending.v);
	free(t->log.v);
	free(t);
}

void pf_tracker_for_each_stack(struct pf_tracker *t,
			       void (*fn)(uint32_t stack, uint64_t bytes, void *ctx),
			       void *ctx)
{
	struct pf_stack *s, *tmp;

	HASH_ITER(hh, t->stacks, s, tmp)
		fn(s->stack, s->bytes, ctx);
}

void pf_tracker_get_stats(const struct pf_tracker *t, struct pf_tracker_stats *out)
{
	*out = t->stats;
	out->stacks = HASH_COUNT(t->stacks);
}
