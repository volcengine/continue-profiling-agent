// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

/*
 * Workload for the VMA-bounded user stack copy (tests/cpa/
 * test_stack_vma.py).
 *
 *   big_frame_app <seconds>
 *
 * Two threads run their leaf under a ~48 KiB frame of which only the lowest
 * page was ever written, like CPython's select_select_impl: the pages between
 * SP and the return address were never faulted in, so a copy that stops at
 * the first unreadable page loses every caller.
 *
 *   vma_spin_thread  -> vma_big_frame -> vma_spin_leaf   (on CPU)
 *   vma_sleep_thread -> vma_big_frame -> vma_sleep_leaf  (off CPU, nanosleep)
 *
 * A third thread parks its SP inside [vvar], a VM_IO/VM_PFNMAP mapping, and
 * spins without touching memory: the bounded copy must read nothing there.
 * It can take no signal (the frame would be pushed onto [vvar]); the process
 * ends by exit_group from main.
 *
 * Prints "ready spin=<tid> sleep=<tid> vvar=<tid>" once all threads run.
 * Build without stack clash protection, which would probe (and so fault in)
 * every page of the frame: -fno-stack-clash-protection -fno-stack-protector.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define BIG_FRAME (48 * 1024)

static volatile unsigned long sink;
static volatile long tids[3];

static void __attribute__((noinline)) vma_spin_leaf(void)
{
	for (;;)
		sink++;
}

static void __attribute__((noinline)) vma_sleep_leaf(void)
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 2 * 1000 * 1000 };

	for (;;)
		nanosleep(&ts, NULL);
}

static void __attribute__((noinline)) vma_big_frame(void (*leaf)(void))
{
	volatile char buf[BIG_FRAME];

	buf[0] = 1;	/* the lowest page only */
	leaf();
	sink += buf[0];
}

static void *vma_spin_thread(void *arg)
{
	(void)arg;
	tids[0] = syscall(SYS_gettid);
	vma_big_frame(vma_spin_leaf);
	return NULL;
}

static void *vma_sleep_thread(void *arg)
{
	(void)arg;
	tids[1] = syscall(SYS_gettid);
	vma_big_frame(vma_sleep_leaf);
	return NULL;
}

static unsigned long vvar_sp(void)
{
	unsigned long start = 0, end = 0;
	char line[512];
	FILE *maps = fopen("/proc/self/maps", "r");

	while (maps && fgets(line, sizeof(line), maps)) {
		if (strstr(line, "[vvar]")) {
			sscanf(line, "%lx-%lx", &start, &end);
			break;
		}
	}
	if (maps)
		fclose(maps);
	return start ? start + 0x800 : 0;	/* in the vDSO data page */
}

static void *vma_vvar_thread(void *arg)
{
	unsigned long sp = (unsigned long)arg;

	tids[2] = syscall(SYS_gettid);
#if defined(__x86_64__)
	__asm__ volatile("mov %0, %%rsp\n1: jmp 1b" : : "r"(sp) : "memory");
#elif defined(__aarch64__)
	__asm__ volatile("mov sp, %0\n1: b 1b" : : "r"(sp) : "memory");
#endif
	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t thread;
	int seconds = argc > 1 ? atoi(argv[1]) : 30;
	unsigned long vvar = vvar_sp();
	struct timespec now;

	/* the vDSO reads [vvar]: fault its data page in, so it is readable */
	clock_gettime(CLOCK_MONOTONIC, &now);

	if (pthread_create(&thread, NULL, vma_spin_thread, NULL) ||
	    pthread_create(&thread, NULL, vma_sleep_thread, NULL) ||
	    (vvar && pthread_create(&thread, NULL, vma_vvar_thread, (void *)vvar)))
		return 1;
	while (!tids[0] || !tids[1] || (vvar && !tids[2]))
		usleep(1000);
	printf("ready spin=%ld sleep=%ld vvar=%ld\n", tids[0], tids[1], tids[2]);
	fflush(stdout);
	sleep(seconds);
	return 0;
}
