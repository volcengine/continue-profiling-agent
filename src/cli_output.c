// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>
#include <sys/time.h>
#include "cli_output.h"
#include <pthread.h>

struct cli_raw_output_ctx {
	int fd;
	bool verbose;
	bool newline;
};

static pthread_spinlock_t raw_output_ctx_lock;
static struct cli_raw_output_ctx raw_output_ctx;
static bool raw_output_ctx_opened;

int open_cli_raw_output(bool verbose)
{
	if (raw_output_ctx_opened)
		return 0;

	if (pthread_spin_init(&raw_output_ctx_lock, PTHREAD_PROCESS_PRIVATE) != 0) {
		fprintf(stderr, "Failed to initialize CLI output lock\n");
		return -1;
	}

	raw_output_ctx.fd = fileno(stdout);
	raw_output_ctx.verbose = verbose;
	raw_output_ctx.newline = true;
	raw_output_ctx_opened = true;

	return 0;
}

void close_cli_raw_output(void)
{
	if (!raw_output_ctx_opened)
		return;

	pthread_spin_lock(&raw_output_ctx_lock);
	if (raw_output_ctx.fd != -1 && raw_output_ctx.fd != STDOUT_FILENO)
		close(raw_output_ctx.fd);
	raw_output_ctx.fd = -1;
	raw_output_ctx.verbose = false;
	raw_output_ctx.newline = true;
	raw_output_ctx_opened = false;
	pthread_spin_unlock(&raw_output_ctx_lock);
	pthread_spin_destroy(&raw_output_ctx_lock);
}

static void cli_printf_time(int fd)
{
	char buffer[20];
	struct timeval tv;
	struct tm *time_info;

	gettimeofday(&tv, NULL);
	time_info = localtime(&tv.tv_sec);

	strftime(buffer, sizeof(buffer), "[%m/%d %H:%M:%S", time_info);
	dprintf(fd, "%s.%04d] ", buffer, (int)(tv.tv_usec / 1000));
}

void cli_raw_output(int level, bool end, const char *format, ...)
{
	int fd = -1;
	va_list arglist;

	if (!raw_output_ctx_opened)
		return;

	if (level == RAW_OUTPUT_VERBOSE && !raw_output_ctx.verbose)
		return;

	pthread_spin_lock(&raw_output_ctx_lock);

	if (!raw_output_ctx_opened) {
		pthread_spin_unlock(&raw_output_ctx_lock);
		return;
	}

	switch (level) {
	case RAW_OUTPUT_ERROR:
		fd = STDERR_FILENO;
		break;
	case RAW_OUTPUT_COMMON:
		fd = raw_output_ctx.fd;
		break;
	case RAW_OUTPUT_VERBOSE:
		fd = raw_output_ctx.fd;
		break;
	default:
		break;
	}

	if (fd == -1) {
		pthread_spin_unlock(&raw_output_ctx_lock);
		return;
	}

	if (raw_output_ctx.newline) {
		cli_printf_time(fd);
		raw_output_ctx.newline = false;
	}

	if (end)
		raw_output_ctx.newline = true;

	va_start(arglist, format);
	vdprintf(fd, format, arglist);
	va_end(arglist);

	if (end)
		dprintf(fd, "\n");

	pthread_spin_unlock(&raw_output_ctx_lock);

	return;
}
