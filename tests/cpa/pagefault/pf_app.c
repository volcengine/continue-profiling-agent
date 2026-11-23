// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

/*
 * Workload for the cpa monitor --pagefault end-to-end test.
 *
 *   pf_app [-m MiB] [-t hold_ms] [-b MiB] [-z MiB] [-x | -L | -E | -F | -H | -D]
 *
 * Build: gcc -O2 -fno-ipa-icf -fno-omit-frame-pointer -pthread (several
 * functions are byte-identical; identical code folding would merge them
 * and with them their stacks).
 *
 * -b touches pf_before MiB and keeps it before waiting: memory resident
 * before the profiler attached.
 * Waits for SIGUSR1 (so the profiler is attached), then touches memory
 * through one function per path the profile must handle, each MiB in size
 * unless noted, and prints "PHASE <name> <CLOCK_REALTIME ms>" lines:
 *
 *   kept:     pf_keep_mmap (2x), pf_thp (2 MiB aligned, MADV_HUGEPAGE),
 *             pf_mremap_move (moved, then kept), pf_heap_trim (malloc'ed)
 *   released: pf_free_mmap (munmap), pf_dontneed (MADV_DONTNEED),
 *             pf_heap_trim (free -> brk shrink), the first MiB of pf_thp
 *             (munmap splitting a huge page) after "released"
 *   never:    pf_file_private_write (private file copy on write),
 *             pf_shared_anon (MAP_SHARED|MAP_ANONYMOUS)
 *
 * After hold_ms it frees the "released" set, holds hold_ms again, then
 * exits (or with -x execs "sleep 3" instead, to test exec).
 *
 * -z reads (never writes) MiB before waiting: zero pages, not memory.
 * -L: after "allocated" the main thread exits; another thread holds the
 * process for hold_ms.  -E runs pf_edge (address-space calls taken
 * literally) instead of the workload.  -F runs pf_fork_cow instead: memory
 * shared with a forked child, copied on write by both.
 * -H runs pf_folio instead: MiB 2 MiB aligned with MADV_HUGEPAGE, so the
 * kernel may back it by folios of any size it is set up for ("REGION folio
 * <addr>"); after "allocated" and hold_ms, MADV_DONTNEED of 1 MiB from
 * 32 KiB in, which cuts folios of 64 KiB and more in two, then "released".
 * -D runs pf_dontunmap instead: MiB moved by mremap(MREMAP_DONTUNMAP) (5.7+),
 * the emptied old range touched again by pf_refill; after "allocated" and
 * hold_ms, the moved MiB are unmapped, then "released".
 *
 * "REGION thp <addr>" names the pf_thp range, so the test can read from
 * /proc/PID/smaps how much of it the kernel backed by huge pages.
 */
#define _GNU_SOURCE
#include <malloc.h>
#include <pthread.h>
#include <stdbool.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MIB (1024UL * 1024UL)

static volatile sig_atomic_t go;
static size_t mib = 32;

static void on_usr1(int sig)
{
	(void)sig;
	go = 1;
}

static long long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000;
}

static void phase(const char *name)
{
	printf("PHASE %s %lld\n", name, now_ms());
	fflush(stdout);
}

static void touch(char *p, size_t len)
{
	for (size_t off = 0; off < len; off += 4096)
		p[off] = 1;
}

static void *anon(size_t len)
{
	void *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	return p == MAP_FAILED ? NULL : p;
}

__attribute__((noinline)) static char *pf_keep_mmap(size_t len)
{
	char *p = anon(len);

	if (p)
		touch(p, len);
	return p;
}

__attribute__((noinline)) static char *pf_before(size_t len)
{
	char *p = anon(len);

	if (p)
		touch(p, len);
	return p;
}

__attribute__((noinline)) static char *pf_free_mmap(size_t len)
{
	char *p = anon(len);

	if (p)
		touch(p, len);
	return p;
}

__attribute__((noinline)) static char *pf_dontneed(size_t len)
{
	char *p = anon(len);

	if (p)
		touch(p, len);
	return p;
}

/* 2 MiB aligned so every huge page can be a PMD mapping */
__attribute__((noinline)) static char *pf_thp(size_t len)
{
	char *raw = anon(len + 2 * MIB), *p;

	if (!raw)
		return NULL;
	p = (char *)(((unsigned long)raw + 2 * MIB - 1) & ~(2 * MIB - 1));
	madvise(p, len, MADV_HUGEPAGE);
	touch(p, len);
	return p;
}

__attribute__((noinline)) static char *pf_mremap_move(size_t len)
{
	char *p = anon(len), *moved;

	if (!p)
		return NULL;
	touch(p, len);
	moved = mremap(p, len, 2 * len, MREMAP_MAYMOVE);
	return moved == MAP_FAILED ? NULL : moved;
}

__attribute__((noinline)) static void pf_file_private_write(size_t len)
{
	char path[] = "pf_app_XXXXXX";	/* in the working directory */
	int fd = mkstemp(path);
	char *p;

	if (fd < 0)
		return;
	unlink(path);
	if (ftruncate(fd, (off_t)len) == 0) {
		p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
		if (p != MAP_FAILED)
			touch(p, len);	/* kept mapped: never counted */
	}
	close(fd);
}

__attribute__((noinline)) static void pf_shared_anon(size_t len)
{
	char *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
		       MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	if (p != MAP_FAILED)
		touch(p, len);
}

/* small blocks on the brk heap; freeing them all lets glibc shrink it */
__attribute__((noinline)) static char **pf_heap_trim(size_t len, size_t *n)
{
	size_t block = 64 * 1024, count = len / block;
	char **blocks = calloc(count, sizeof(*blocks));

	for (size_t i = 0; blocks && i < count; i++) {
		blocks[i] = malloc(block - 64);
		if (blocks[i])
			touch(blocks[i], block - 64);
	}
	*n = count;
	return blocks;
}

/* Read, never written: mapped to the shared zero page. */
__attribute__((noinline)) static char *pf_zero(size_t len)
{
	volatile char *p = anon(len);
	char sum = 0;

	for (size_t off = 0; p && off < len; off += 4096)
		sum += p[off];
	(void)sum;
	return (char *)p;
}

__attribute__((noinline)) static char *pf_edge_dest(size_t len)
{
	char *p = anon(len);

	if (p)
		touch(p, len);
	return p;
}

/*
 * Address-space calls the profile must take literally: failed calls
 * release nothing, lengths count in whole pages, MREMAP_FIXED replaces the
 * target.  Leaves exactly len bytes charged to pf_edge, none to
 * pf_edge_dest.
 */
__attribute__((noinline)) static void pf_edge(size_t len)
{
	char *p = anon(len), *src = anon(4096), *dst = pf_edge_dest(2 * 4096);
	long brk_now;

	if (!p || !src || !dst)
		return;
	touch(p, len);
	touch(src, 4096);
	/* all fail: unaligned, MADV_REMOVE of private memory, bad fd, low brk */
	if (munmap(p + 1, 4096) == 0 || madvise(p, len, MADV_REMOVE) == 0 ||
	    mmap(p, 4096, PROT_READ, MAP_PRIVATE | MAP_FIXED, -1, 0) != MAP_FAILED)
		fprintf(stderr, "pf_edge: a call expected to fail succeeded\n");
	brk_now = syscall(SYS_brk, 0);
	if (syscall(SYS_brk, 1) != brk_now)
		fprintf(stderr, "pf_edge: brk(1) moved the break\n");
	/* one byte: the whole last page */
	munmap(p + len - 4096, 1);
	/* onto the two pages of pf_edge_dest, growing to two pages */
	if (mremap(src, 4096, 2 * 4096, MREMAP_MAYMOVE | MREMAP_FIXED, dst) == MAP_FAILED)
		fprintf(stderr, "pf_edge: mremap failed\n");
}

__attribute__((noinline)) static char *pf_folio(size_t len)
{
	char *raw = anon(len + 2 * MIB), *p;

	if (!raw)
		return NULL;
	p = (char *)(((unsigned long)raw + 2 * MIB - 1) & ~(2 * MIB - 1));
	madvise(p, len, MADV_HUGEPAGE);
	touch(p, len);
	return p;
}

#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif

__attribute__((noinline)) static void pf_refill(char *p, size_t len)
{
	touch(p, len);
}

/* The pages move; the old range stays mapped, empty, and is refilled. */
__attribute__((noinline)) static char *pf_dontunmap(size_t len)
{
	char *p = anon(len), *moved;

	if (!p)
		return NULL;
	touch(p, len);
	/* glibc passes no new address without MREMAP_FIXED: the kernel would
	 * read a stray register as the hint */
	moved = (char *)syscall(SYS_mremap, p, len, len,
				MREMAP_MAYMOVE | MREMAP_DONTUNMAP, 0UL);
	if (moved == MAP_FAILED) {
		fprintf(stderr, "pf_dontunmap: unsupported\n");
		return NULL;
	}
	pf_refill(p, len);
	return moved;
}

__attribute__((noinline)) static void pf_child_touch(char *p, size_t len)
{
	touch(p, len);
}

__attribute__((noinline)) static void pf_cow_write(char *p, size_t len)
{
	touch(p, len);
}

/*
 * len bytes kept by pf_keep_mmap, then shared with a forked child.  The
 * parent writes them while the child still maps them: every page is copied
 * on write, a new anonymous page at an address already live -- not more
 * memory.  The child's own memory and its copies are another process's.
 */
__attribute__((noinline)) static void pf_fork_cow(size_t len)
{
	char *keep = pf_keep_mmap(len), *own = anon(len), c = 0;
	int to_child[2], to_parent[2];
	pid_t pid;

	if (!keep || !own || pipe(to_child) || pipe(to_parent)) {
		fprintf(stderr, "pf_fork_cow: setup failed\n");
		return;
	}
	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "pf_fork_cow: fork failed\n");
		return;
	}
	if (pid == 0) {
		pf_child_touch(own, len);
		if (write(to_parent[1], &c, 1) != 1 || read(to_child[0], &c, 1) != 1)
			_exit(1);
		pf_child_touch(keep, len);	/* its own copies */
		_exit(0);
	}
	if (read(to_parent[0], &c, 1) != 1)
		fprintf(stderr, "pf_fork_cow: child gone\n");
	pf_cow_write(keep, len);
	phase("cow");
	if (write(to_child[1], &c, 1) != 1 || waitpid(pid, NULL, 0) != pid)
		fprintf(stderr, "pf_fork_cow: child lost\n");
	phase("child_exit");
}

static long hold_ms = 5000;

static void *hold_then_exit(void *arg)
{
	(void)arg;
	usleep(hold_ms * 1000);
	phase("exit");
	exit(0);
}

int main(int argc, char **argv)
{
	size_t before_mib = 0, zero_mib = 0;
	bool exec_after = false, leader_exit = false, edge = false, fork_cow = false;
	bool folio = false, dontunmap = false;
	char **heap;
	size_t heap_n = 0;
	char *freed, *dontneed, *thp;
	int opt;

	while ((opt = getopt(argc, argv, "m:t:b:xz:LEFHD")) != -1) {
		switch (opt) {
		case 'z': zero_mib = strtoul(optarg, NULL, 10); break;
		case 'L': leader_exit = true; break;
		case 'E': edge = true; break;
		case 'F': fork_cow = true; break;
		case 'H': folio = true; break;
		case 'D': dontunmap = true; break;
		case 'b': before_mib = strtoul(optarg, NULL, 10); break;
		case 'm': mib = strtoul(optarg, NULL, 10); break;
		case 't': hold_ms = atol(optarg); break;
		case 'x': exec_after = true; break;
		default: return 2;
		}
	}
	/* heap blocks must come from brk, not mmap */
	mallopt(M_MMAP_THRESHOLD, 1024 * 1024);
	mallopt(M_TRIM_THRESHOLD, 128 * 1024);
	signal(SIGUSR1, on_usr1);
	if (before_mib)
		pf_before(before_mib * MIB);
	if (zero_mib)
		pf_zero(zero_mib * MIB);
	phase("ready");
	while (!go)
		pause();

	phase("start");
	if (edge) {
		pf_edge(mib * MIB);
		phase("allocated");
		usleep(hold_ms * 1000);
		phase("exit");
		return 0;
	}
	if (fork_cow) {
		pf_fork_cow(mib * MIB);
		phase("allocated");
		usleep(hold_ms * 1000);
		phase("exit");
		return 0;
	}
	if (folio) {
		char *p = pf_folio(mib * MIB);

		printf("REGION folio %lx\n", (unsigned long)p);
		phase("allocated");
		usleep(hold_ms * 1000);
		if (p)
			madvise(p + 32 * 1024, MIB, MADV_DONTNEED);
		phase("released");
		usleep(hold_ms * 1000);
		phase("exit");
		return 0;
	}
	if (dontunmap) {
		char *moved = pf_dontunmap(mib * MIB);

		phase("allocated");
		usleep(hold_ms * 1000);
		if (moved)
			munmap(moved, mib * MIB);
		phase("released");
		usleep(hold_ms * 1000);
		phase("exit");
		return 0;
	}
	pf_keep_mmap(2 * mib * MIB);
	freed = pf_free_mmap(mib * MIB);
	dontneed = pf_dontneed(mib * MIB);
	thp = pf_thp(mib * MIB);
	printf("REGION thp %lx\n", (unsigned long)thp);
	pf_mremap_move(mib * MIB);
	pf_file_private_write(mib * MIB);
	pf_shared_anon(mib * MIB);
	heap = pf_heap_trim(mib * MIB, &heap_n);
	phase("allocated");
	if (leader_exit) {
		/* the main thread leaves; the process and its memory stay */
		pthread_t worker;

		pthread_create(&worker, NULL, hold_then_exit, NULL);
		phase("leader_exit");
		pthread_exit(NULL);
	}
	usleep(hold_ms * 1000);

	munmap(freed, mib * MIB);
	madvise(dontneed, mib * MIB, MADV_DONTNEED);
	if (thp)
		munmap(thp, MIB);
	for (size_t i = heap_n; heap && i-- > 0;)
		free(heap[i]);
	malloc_trim(0);
	phase("released");
	usleep(hold_ms * 1000);

	phase("exit");
	if (exec_after)
		execl("/bin/sleep", "sleep", "3", (char *)NULL);
	return 0;
}
