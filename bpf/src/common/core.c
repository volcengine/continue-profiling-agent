// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#define _GNU_SOURCE
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <cpa_bpf.h>

#include "btf_helpers.h"
#include "bpf_event_poll.h"
#include "core.h"
#define __BPF_DEFINE_FN(x) extern const struct bpf_module_ops bpf_module_##x;
__BPF_MODULE(__BPF_DEFINE_FN)
#undef __BPF_DEFINE_FN

#define __BPF_MODULE_FN(x) [BPF_MODULE_##x] = &bpf_module_##x,
static const struct bpf_module_ops *const bpf_modules[] = { __BPF_MODULE(__BPF_MODULE_FN) };
#undef __BPF_MODULE_FN

#define __BPF_MODULE_FN(x) [BPF_MODULE_##x] = #x,
static const char *const bpf_modules_name[] = { __BPF_MODULE(__BPF_MODULE_FN) };
#undef __BPF_MODULE_FN

static unsigned long bpf_module_mask;
static bool bpf_init_done;
bool __cpa_bpf_verbose;

static struct bpf_object_open_opts open_opts = {
	.sz = sizeof(struct bpf_object_open_opts),
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
#ifndef DEBUG
	if (level == LIBBPF_DEBUG)
		return 0;
#endif
	if (level == LIBBPF_WARN) {
		fprintf(stderr, "[BPF][WARN] ");
		return vfprintf(stderr, format, args);
	}
	if (level == LIBBPF_INFO) {
		if (!__cpa_bpf_verbose)
			return 0;
		fprintf(stderr, "[BPF][INFO] ");
		return vfprintf(stderr, format, args);
	}
	if (level == LIBBPF_DEBUG) {
		if (!__cpa_bpf_verbose)
			return 0;
		fprintf(stderr, "[BPF][INFO] ");
		return vfprintf(stderr, format, args);
	}
	fprintf(stderr, "[BPF][ERR] ");
	return vfprintf(stderr, format, args);
}

__u32 get_module_version(const char *name, const char *version)
{
	__u32 major, minor, patch = 0;

	if (sscanf(version, "%u.%u.%u", &major, &minor, &patch) < 2) {
		BPF_WARN("module %s kernel version wrong: %s\n", name, version);
		return 0;
	}
	return KERNEL_VERSION(major, minor, patch);
}

int bpf_module_ctl(unsigned long mask)
{
	__u32 kv = get_kernel_version();
	unsigned long enable_mask;
	int i;

	if (!bpf_init_done) {
		BPF_WARN("not init yet. Must call init_bpf()\n");
		return -1;
	}

	BPF_INFO("module_ctl mask=0x%lx\n", mask);
	enable_mask = mask;
	for (i = 0; i < __BPF_MODULE_MAX_ID; i++) {
		const char *name = bpf_modules_name[i];
		const char *version = bpf_modules[i]->kernel_version;
		__u32 mkv = get_module_version(name, version);

		if ((enable_mask & (1UL << i)) && !(bpf_module_mask & (1UL << i))) {
			if (mkv == 0 || mkv > kv) {
				BPF_WARN("module %s need kernel version %s\n", name, version);
				continue;
			}

			if (bpf_modules[i]->init_bpf_module(&open_opts)) {
				BPF_WARN("module %s init failed\n", bpf_modules_name[i]);
				bpf_modules[i]->exit_bpf_module();
				continue;
			}

			bpf_module_mask |= (1UL << i);

			BPF_INFO("module %s init success\n", bpf_modules_name[i]);
		} else if (!(enable_mask & (1UL << i)) && (bpf_module_mask & (1UL << i))) {
			bpf_module_mask &= ~(1UL << i);
			bpf_modules[i]->exit_bpf_module();
			BPF_INFO("module %s disabled\n", bpf_modules_name[i]);
		}
	}

	return 0;
}

static bool user_defined_btf_path;

int init_bpf(struct cpa_bpf_init_options *options)
{
	int err;

	/* Allow libbpf to pin maps and load programs without memlock failures. */
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (bpf_init_done) {
		BPF_INFO("init already done\n");
		return 0;
	}

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		BPF_WARN("failed to increase RLIMIT_MEMLOCK limit\n");
		return -1;
	}

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);
	err = bpf_event_poll_init();
	if (err) {
		BPF_WARN("failed to init bpf event poll\n");
		return -1;
	}

	if (options->btf_path && !access(options->btf_path, R_OK)) {
		open_opts.btf_custom_path = strdup(options->btf_path);
		user_defined_btf_path = true;
		BPF_INFO("use user defined BTF: %s\n", options->btf_path);
	} else {
		/*
		 * BTF selection is resolved before any module load: explicit user
		 * BTF wins; otherwise use system vmlinux BTF or extracted CO-RE BTF.
		 */
		err = ensure_core_btf(&open_opts);
		if (err) {
			BPF_WARN("failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
			goto cleanup;
		}
	}

	bpf_init_done = true;

	if (bpf_module_ctl(options->mask)) {
		BPF_WARN("module_ctl failed\n");
		goto cleanup;
	}

	BPF_INFO("started\n");
	return 0;

cleanup:
	free_bpf();
	return -1;
}

void free_bpf()
{
	int i;

	bpf_init_done = false;
	bpf_event_poll_destroy();

	for (i = 0; i < __BPF_MODULE_MAX_ID; i++) {
		if (bpf_module_mask & (1UL << i)) {
			bpf_modules[i]->exit_bpf_module();
			bpf_module_mask &= ~(1UL << i);
		}
	}

	if (open_opts.btf_custom_path && !user_defined_btf_path) {
		cleanup_core_btf(&open_opts);
	} else {
		free((void *)open_opts.btf_custom_path);
	}

	open_opts.btf_custom_path = NULL;
	user_defined_btf_path = false;

	BPF_INFO("stopped\n");
}

unsigned long get_bpf_mask(void)
{
	return bpf_module_mask;
}

void set_cpa_bpf_verbose(void)
{
	__cpa_bpf_verbose = true;
}
