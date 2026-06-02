// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <zlib.h>

#include <bpf/bpf.h>
#include <linux/bpf.h>

#include "trace_helpers.h"
#include "btf_helpers.h"
#include "core.h"

#define BTF_VPRINT(fmt, ...)                                                                                                                                                                                                                                   \
	do {                                                                                                                                                                                                                                                   \
		if (__cpa_bpf_verbose)                                                                                                                                                                                                                         \
			fprintf(stderr, "[BPF][INFO] btf " fmt, ##__VA_ARGS__);                                                                                                                                                                                \
	} while (0)

#ifndef CPA_HAVE_MIN_CORE_BTF
#define CPA_HAVE_MIN_CORE_BTF 0
#endif

#if CPA_HAVE_MIN_CORE_BTF
extern unsigned char _binary_min_core_btfs_tar_gz_start[];
extern unsigned char _binary_min_core_btfs_tar_gz_end[];
#endif

#define ID_FMT "ID=%64s"
#define VERSION_FMT "VERSION_ID=\"%64s"

void remove_quotes(char *str)
{
	if (str == NULL || *str == '\0') {
		return;
	}

	size_t len = strlen(str);

	if (len == 1) {
		return;
	}

	if (str[0] == '"' && str[len - 1] == '"') {
		memmove(str, str + 1, len - 1);
		str[len - 2] = '\0';
	}
}

struct os_info *get_os_info()
{
	struct os_info *info = NULL;
	struct utsname u;
	size_t len = 0;
	ssize_t read;
	char *line = NULL;
	FILE *f;

	if (uname(&u) == -1)
		return NULL;

	f = fopen("/etc/os-release", "r");
	if (!f)
		return NULL;

	info = calloc(1, sizeof(*info));
	if (!info)
		goto out;

	strncpy(info->kernel_release, u.release, FIELD_LEN);
	if (strncmp("aarch64", u.machine, sizeof("aarch64")) == 0)
		strncpy(info->arch, "arm64", FIELD_LEN);
	else
		strncpy(info->arch, u.machine, FIELD_LEN);

	while ((read = getline(&line, &len, f)) != -1) {
		if (sscanf(line, ID_FMT, info->id) == 1)
			continue;

		if (sscanf(line, VERSION_FMT, info->version) == 1) {
			/* remove '"' suffix */
			info->version[strlen(info->version) - 1] = 0;
			continue;
		}
	}

	remove_quotes(info->id);

out:
	free(line);
	fclose(f);

	return info;
}

#define INITIAL_BUF_SIZE (1024 * 1024 * 4) /* 4MB */

static void debug_print_kernel_btf_objects(void)
{
	__u32 id = 0, next_id = 0;

	if (!__cpa_bpf_verbose)
		return;

	BTF_VPRINT("kernel BTF objects:\n");
	while (bpf_btf_get_next_id(id, &next_id) == 0) {
		struct bpf_btf_info info;
		char name_buf[BPF_OBJ_NAME_LEN];
		__u32 info_len = sizeof(info);
		int fd;

		memset(name_buf, 0, sizeof(name_buf));
		memset(&info, 0, sizeof(info));
		info.name = (__u64)(unsigned long)name_buf;
		info.name_len = sizeof(name_buf);
		fd = bpf_btf_get_fd_by_id(next_id);
		if (fd < 0) {
			BTF_VPRINT("  id=%u fd_by_id failed errno=%d (%s)\n", next_id, errno, strerror(errno));
			id = next_id;
			continue;
		}

		if (bpf_obj_get_info_by_fd(fd, &info, &info_len) != 0) {
			BTF_VPRINT("  id=%u obj_info failed errno=%d (%s)\n", next_id, errno, strerror(errno));
			close(fd);
			id = next_id;
			continue;
		}

		BTF_VPRINT("  id=%u name=%s kernel_btf=%u btf_size=%u\n", next_id, name_buf[0] ? name_buf : "(unknown)", info.kernel_btf, info.btf_size);
		close(fd);
		id = next_id;
	}
}

/* adapted from https://zlib.net/zlib_how.html */
#if CPA_HAVE_MIN_CORE_BTF
static int inflate_gz(unsigned char *src, int src_size, unsigned char **dst, int *dst_size)
{
	size_t size = INITIAL_BUF_SIZE;
	size_t next_size = size;
	z_stream strm;
	void *tmp;
	int ret;

	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	strm.avail_in = 0;
	strm.next_in = Z_NULL;

	ret = inflateInit2(&strm, 16 + MAX_WBITS);
	if (ret != Z_OK)
		return -EINVAL;

	*dst = malloc(size);
	if (!*dst)
		return -ENOMEM;

	strm.next_in = src;
	strm.avail_in = src_size;

	/* run inflate() on input until it returns Z_STREAM_END */
	do {
		strm.next_out = *dst + strm.total_out;
		strm.avail_out = next_size;
		ret = inflate(&strm, Z_NO_FLUSH);
		if (ret != Z_OK && ret != Z_STREAM_END)
			goto out_err;
		/* we need more space */
		if (strm.avail_out == 0) {
			next_size = size;
			size *= 2;
			tmp = realloc(*dst, size);
			if (!tmp) {
				ret = -ENOMEM;
				goto out_err;
			}
			*dst = tmp;
		}
	} while (ret != Z_STREAM_END);

	*dst_size = strm.total_out;

	/* clean up and return */
	ret = inflateEnd(&strm);
	if (ret != Z_OK) {
		ret = -EINVAL;
		goto out_err;
	}
	return 0;

out_err:
	free(*dst);
	*dst = NULL;
	return ret;
}
#endif

/* tar header from https://github.com/tklauser/libtar/blob/v1.2.20/lib/libtar.h#L39-L60 */
struct tar_header {
	char name[100];
	char mode[8];
	char uid[8];
	char gid[8];
	char size[12];
	char mtime[12];
	char chksum[8];
	char typeflag;
	char linkname[100];
	char magic[6];
	char version[2];
	char uname[32];
	char gname[32];
	char devmajor[8];
	char devminor[8];
	char prefix[155];
	char padding[12];
};

static char *tar_file_start(struct tar_header *tar, const char *name, int *length)
{
	while (tar->name[0]) {
		sscanf(tar->size, "%o", length);
		if (!strcmp(tar->name, name))
			return (char *)(tar + 1);
		tar += 1 + (*length + 511) / 512;
	}
	return NULL;
}

int ensure_core_btf(struct bpf_object_open_opts *opts)
{
	char name_fmt[] = "./%s/%s/%s/%s.btf";
	char btf_path[] = "/tmp/bcc-libbpf-tools.btf.XXXXXX";
	struct os_info *info = NULL;
	unsigned char *dst_buf = NULL;
	char *file_start;
	int dst_size = 0;
	char name[100];
	FILE *dst = NULL;
	int ret;

	BTF_VPRINT("ensure_core_btf: enter\n");
	BTF_VPRINT("try sysfs vmlinux btf: /sys/kernel/btf/vmlinux (readable=%d)\n", vmlinux_btf_exists() ? 1 : 0);
	debug_print_kernel_btf_objects();

	/* Fast path: system BTF needs no temporary extraction or custom path. */
	if (vmlinux_btf_exists()) {
		BTF_VPRINT("FOUND system vmlinux BTF: /sys/kernel/btf/vmlinux\n");
		return 0;
	}

	info = get_os_info();
	if (!info)
		return -errno;

	BTF_VPRINT("os_info: id=%s version=%s arch=%s kernel_release=%s\n", info->id, info->version, info->arch, info->kernel_release);

	ret = mkstemp(btf_path);
	if (ret < 0) {
		ret = -errno;
		goto out;
	}

	dst = fdopen(ret, "wb");
	if (!dst) {
		ret = -errno;
		goto out;
	}

	ret = snprintf(name, sizeof(name), name_fmt, info->id, info->version, info->arch, info->kernel_release);
	if (ret < 0 || ret == sizeof(name)) {
		ret = -EINVAL;
		goto out;
	}
	/*
	 * Embedded BTF entries are keyed by OS id/version, architecture, and
	 * kernel release. A miss means CO-RE cannot be made safe for this host.
	 */
	BTF_VPRINT("try embedded BTF entry: %s\n", name);

#if CPA_HAVE_MIN_CORE_BTF
	ret = inflate_gz(_binary_min_core_btfs_tar_gz_start, _binary_min_core_btfs_tar_gz_end - _binary_min_core_btfs_tar_gz_start, &dst_buf, &dst_size);
	if (ret < 0)
		goto out;
#else
	ret = -ENOENT;
	goto out;
#endif

	ret = 0;
	file_start = tar_file_start((struct tar_header *)dst_buf, name, &dst_size);
	if (!file_start) {
		BPF_WARN("can't find BTF for release: %s\n", name);
		ret = -EINVAL;
		goto out;
	}
	BTF_VPRINT("FOUND embedded BTF entry: %s\n", name);
	BTF_VPRINT("write extracted BTF to temp file: %s (size=%d)\n", btf_path, dst_size);

	if (fwrite(file_start, 1, dst_size, dst) != dst_size) {
		ret = -ferror(dst);
		goto out;
	}

	opts->btf_custom_path = strdup(btf_path);
	if (!opts->btf_custom_path)
		ret = -ENOMEM;
	else
		BTF_VPRINT("opts->btf_custom_path: %s\n", opts->btf_custom_path);

out:
	free(info);
	if (dst)
		fclose(dst);
	free(dst_buf);

	return ret;
}

void cleanup_core_btf(struct bpf_object_open_opts *opts)
{
	if (!opts)
		return;

	if (!opts->btf_custom_path)
		return;

	unlink(opts->btf_custom_path);
	free((void *)opts->btf_custom_path);
}
