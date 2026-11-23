// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance
/*
 * Workload for run_exit_e2e.py: argv[1] picks one exit path.  The binary is
 * copied under one name per path so each run has its own comm.
 *
 * Build: gcc -O0 -g -fno-omit-frame-pointer -pthread exit_app.c -o exit_app
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static pthread_barrier_t race_barrier;

__attribute__((noinline)) static void spin_forever(void)
{
	for (;;)
		pause();
}

__attribute__((noinline)) static void *worker_exit_fn(void *arg)
{
	(void)arg;
	usleep(100000);
	syscall(SYS_exit_group, 3);
	return NULL;
}

__attribute__((noinline)) static void *worker_late_exit_fn(void *arg)
{
	(void)arg;
	usleep(500000);
	syscall(SYS_exit_group, 1);
	return NULL;
}

__attribute__((noinline)) static void *worker_spin_fn(void *arg)
{
	(void)arg;
	spin_forever();
	return NULL;
}

__attribute__((noinline)) static void *exec_fn(void *arg)
{
	char *const argv[] = { (char *)arg, "zero", NULL };

	usleep(100000);
	/* de_thread() zaps the leader with SIGKILL; the group's code stays 0 */
	execv("/proc/self/exe", argv);
	return NULL;
}

__attribute__((noinline)) static void *race_fn(void *arg)
{
	pthread_barrier_wait(&race_barrier);
	syscall(SYS_exit_group, (int)(long)arg);
	return NULL;
}

/*
 * Two seconds on CPU in libc system calls before exit_group(4): sampled
 * while it lives, unlike the sleeping modes.  Its frames still depend on
 * when its view of the mappings was read (see run_exit_e2e.py).
 */
__attribute__((noinline)) static void *busy_exit_fn(void *arg)
{
	struct timespec start, now;

	(void)arg;
	clock_gettime(CLOCK_MONOTONIC, &start);
	do {
		getppid();
		clock_gettime(CLOCK_MONOTONIC, &now);
	} while (now.tv_sec - start.tv_sec < 2);
	syscall(SYS_exit_group, 4);
	return NULL;
}

/* A call through a NULL function pointer: the fault's PC is 0. */
static void (*volatile null_fn)(void);

__attribute__((noinline)) static void *nullcall_fn(void *arg)
{
	(void)arg;
	usleep(100000);
	null_fn();
	return NULL;
}

__attribute__((noinline)) static void *segv_fn(void *arg)
{
	(void)arg;
	usleep(100000);
	*(volatile int *)8 = 1;
	return NULL;
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "";
	struct rlimit no_core = { 0, 0 };
	pthread_t t1, t2;

	/* do_coredump is still entered; only the core file is skipped */
	setrlimit(RLIMIT_CORE, &no_core);
	/* short lived: exit_group(1) 50 ms after exec, or at once */
	if (!strcmp(mode, "short")) {
		usleep(50000);
		syscall(SYS_exit_group, 1);
	} else if (!strcmp(mode, "flash")) {
		syscall(SYS_exit_group, 1);
	}
	/* give the session time to select and preheat this process */
	usleep(800000);
	if (!strcmp(mode, "sysexit")) {
		syscall(SYS_exit, 7);
	} else if (!strcmp(mode, "nullcall")) {
		pthread_create(&t1, NULL, nullcall_fn, NULL);
		pthread_join(t1, NULL);
	} else if (!strcmp(mode, "busy")) {
		pthread_create(&t1, NULL, busy_exit_fn, NULL);
		pthread_join(t1, NULL);
	} else if (!strcmp(mode, "worker")) {
		pthread_create(&t1, NULL, worker_exit_fn, NULL);
		pthread_join(t1, NULL);
	} else if (!strcmp(mode, "ldexit")) {
		pthread_create(&t1, NULL, worker_late_exit_fn, NULL);
		pthread_exit(NULL);
	} else if (!strcmp(mode, "ldkill")) {
		pthread_create(&t1, NULL, worker_spin_fn, NULL);
		pthread_exit(NULL);
	} else if (!strcmp(mode, "term")) {
		spin_forever();
	} else if (!strcmp(mode, "race")) {
		pthread_barrier_init(&race_barrier, NULL, 2);
		pthread_create(&t1, NULL, race_fn, (void *)5L);
		pthread_create(&t2, NULL, race_fn, (void *)6L);
		pthread_join(t1, NULL);
	} else if (!strcmp(mode, "segv")) {
		/* a bystander thread exists so the dump zaps someone */
		pthread_create(&t1, NULL, worker_spin_fn, NULL);
		pthread_create(&t2, NULL, segv_fn, NULL);
		pthread_join(t2, NULL);
	} else if (!strcmp(mode, "exec")) {
		pthread_create(&t1, NULL, exec_fn, argv[0]);
		spin_forever();
	} else if (!strcmp(mode, "zero")) {
		syscall(SYS_exit_group, 0);
	} else if (!strcmp(mode, "fork")) {
		/* a child process without exec: exit_group(2); the parent 0 */
		pid_t child = fork();

		if (child == 0) {
			usleep(300000);
			syscall(SYS_exit_group, 2);
		}
		waitpid(child, NULL, 0);
		syscall(SYS_exit_group, 0);
	} else if (!strcmp(mode, "execto") && argc > 3) {
		/* become argv[2] (another name) running mode argv[3] */
		char *const args[] = { argv[2], argv[3], NULL };

		execv(argv[2], args);
	}
	return 99;
}
