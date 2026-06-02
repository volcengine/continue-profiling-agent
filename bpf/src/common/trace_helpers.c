/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
// Copyright (c) 2020 Wenbo Zhang
// Copyright (c) 2024 Bytedance
//
// Based on ksyms improvements from Andrii Nakryiko, add more helpers.
// 28-Feb-2020   Wenbo Zhang   Created this.
// 11-Mar-2024   Yuchen Zhang  Add more helpers.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <time.h>
#include <limits.h>
#include "trace_helpers.h"
#include "core.h"

#define min(x, y)                                                                                                                                                                                                                                              \
	({                                                                                                                                                                                                                                                     \
		typeof(x) _min1 = (x);                                                                                                                                                                                                                         \
		typeof(y) _min2 = (y);                                                                                                                                                                                                                         \
		(void)(&_min1 == &_min2);                                                                                                                                                                                                                      \
		_min1 < _min2 ? _min1 : _min2;                                                                                                                                                                                                                 \
	})

#define DISK_NAME_LEN 32
#define DISK_NAME_SCAN_LEN 31

#define STRINGIFY(x) __STRINGIFY(x)
#define __STRINGIFY(x) #x

#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1)

#define MKDEV(ma, mi) (((ma) << MINORBITS) | (mi))

int find_ksyms_addr(const char *names[], unsigned long *addrs, int count)
{
	FILE *f;
	char sym_type, sym_name[256];
	unsigned long sym_addr;
	int ret;
	size_t i;
	size_t found = 0;
	char *matched;

	if (!names || !addrs || count == 0)
		return 0;

	for (i = 0; i < count; i++)
		addrs[i] = 0;

	matched = (char *)calloc(count, 1);
	if (!matched)
		return -1;

	f = fopen("/proc/kallsyms", "r");
	if (!f) {
		free(matched);
		return -1;
	}

	while (1) {
		ret = fscanf(f, "%lx %c %255s%*[\n]", &sym_addr, &sym_type, sym_name);
		if (ret == EOF && feof(f))
			break;
		if (ret != 3) {
			/* skip malformed line */
			int c;
			while ((c = fgetc(f)) != '\n' && c != EOF) {
			}
			continue;
		}
		for (i = 0; i < count; i++) {
			if (matched[i])
				continue;
			if (strcmp(sym_name, names[i]) == 0) {
				addrs[i] = sym_addr;
				matched[i] = 1;
				found++;
				if (found == count)
					goto out;
			}
		}
	}

out:
	fclose(f);
	free(matched);
	return (int)found;
}

bool kprobe_exists(const char *name)
{
	char sym_name[256];
	FILE *f;
	int ret;

	f = fopen("/sys/kernel/debug/tracing/available_filter_functions", "r");
	if (!f)
		goto slow_path;

	while (true) {
		ret = fscanf(f, "%255s%*[^\n]\n", sym_name);
		if (ret == EOF && feof(f))
			break;
		if (ret != 1) {
			BPF_ERR("failed to read symbol from available_filter_functions\n");
			break;
		}
		if (!strcmp(name, sym_name)) {
			fclose(f);
			return true;
		}
	}

	fclose(f);
	return false;

slow_path:
	f = fopen("/proc/kallsyms", "r");
	if (!f)
		return false;

	while (true) {
		ret = fscanf(f, "%*x %*c %255s%*[^\n]\n", sym_name);
		if (ret == EOF && feof(f))
			break;
		if (ret != 1) {
			BPF_ERR("failed to read symbol from kallsyms\n");
			break;
		}
		if (!strcmp(name, sym_name)) {
			fclose(f);
			return true;
		}
	}

	fclose(f);
	return false;
}

bool vmlinux_btf_exists(void)
{
	if (!access("/sys/kernel/btf/vmlinux", R_OK))
		return true;
	return false;
}

bool module_btf_exists(const char *mod)
{
	char sysfs_mod[80];

	if (mod) {
		snprintf(sysfs_mod, sizeof(sysfs_mod), "/sys/kernel/btf/%s", mod);
		if (!access(sysfs_mod, R_OK))
			return true;
	}
	return false;
}

bool kernel_config_enabled(const char *config)
{
	char *val = kernel_config_value(config);
	if (strncmp("y", val, 1) != 0) {
		free(val);
		return false;
	}
	free(val);
	return true;
}

char *kernel_config_value(const char *config)
{
	char config_file[256];
	char line[512];

	FILE *uname_file = popen("uname -r", "r");
	if (!uname_file) {
		BPF_ERR("failed to get kernel version\n");
		return strdup("n");
	}

	char kernel_version[128];
	if (fgets(kernel_version, sizeof(kernel_version), uname_file) == NULL) {
		BPF_ERR("failed to get kernel version\n");
		pclose(uname_file);
		return strdup("n");
	}
	pclose(uname_file);

	kernel_version[strcspn(kernel_version, "\n")] = 0;

	snprintf(config_file, sizeof(config_file), "/boot/config-%s", kernel_version);

	FILE *file = fopen(config_file, "r");
	if (!file) {
		BPF_ERR("failed to get config file\n");
		return strdup("n");
	}

	while (fgets(line, sizeof(line), file) != NULL) {
		size_t config_len = strlen(config);
		if (strncmp(line, config, config_len) == 0 && (line[config_len] == '=' || line[config_len] == '\0')) {
			fclose(file);
			char *value = strchr(line, '=');
			if (value) {
				value++; // Skip the '=' character
				value[strcspn(value, "\n")] = 0; // Remove newline character
				return strdup(value);
			} else {
				return strdup("n");
			}
		}
	}

	fclose(file);
	return strdup("n");
}

#ifdef __CPA_BPF_ARCH_x86

#include <cpuid.h>

static int cpu_has_la57(void)
{
	unsigned int eax, ebx, ecx, edx;

	if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx))
		return ecx & (1 << 16);

	return 0;
}

unsigned long get_task_size_max(void)
{
	if (cpu_has_la57())
		return (1ul << 56) - 0x1000;
	else
		return (1ul << 47) - 0x1000;
}

#elif defined(__CPA_BPF_ARCH_arm64)

unsigned long get_task_size_max(void)
{
	char *va_bits_str = kernel_config_value("CONFIG_ARM64_VA_BITS");
	unsigned long va_bits = 0;

	if (va_bits_str) {
		if (strcmp(va_bits_str, "n") != 0)
			va_bits = strtol(va_bits_str, NULL, 10);
		free(va_bits_str);
	}

	if (va_bits == 0)
		va_bits = 48;

	return (1UL << va_bits);
}

#endif

#define KALLSYMS_PATH "/proc/kallsyms"

char *find_kprobe_functions(const char *func)
{
	FILE *file;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	char *result = NULL;
	char prefix[256];

	snprintf(prefix, sizeof(prefix), "%s.", func);

	file = fopen(KALLSYMS_PATH, "r");
	if (!file)
		goto out;

	while ((read = getline(&line, &len, file)) != -1) {
		char *symbol;

		symbol = strrchr(line, ' ');
		if (!symbol)
			continue;
		symbol++;

		symbol[strcspn(symbol, "\n")] = '\0';

		if (strcmp(symbol, func) == 0) {
			result = strdup(symbol);
			goto out;
		}

		if (!result && strncmp(symbol, prefix, strlen(prefix)) == 0) {
			result = strdup(symbol);
		}
	}

out:
	if (file)
		fclose(file);
	if (line)
		free(line);

	return result;
}
