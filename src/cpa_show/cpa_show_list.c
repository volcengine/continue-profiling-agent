// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

/*
 * `cpa show --list_core` / `--list_exit`: the COREDUMP or EXIT NONZERO
 * samples of a store, one block each, with their crash-level frames and,
 * with --core_verbose, source lines from addr2line (through the build-id
 * debug files when the binary has none).
 */

#include "cpa_show_list.h"
#include "cli.h"
#include "cli_cmd_helper.h"
#include "cli_common.h"
#include "cli_profile_metadata.h"
#include "cli_stackmap.h"
#include "cli_stackmap_private.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CPA_ADDR2LINE_ENV "CPA_ADDR2LINE"
#define CPA_CORE_DEBUG_DIR_ENV "CPA_CORE_DEBUG_DIR"
#define CPA_CORE_CGROUP_ROOT_HINT_ENV "CPA_CORE_CGROUP_ROOT_HINT"
#define COREDUMP_MARKER_PREFIX "<# COREDUMP "
#define EXIT_MARKER_PREFIX "<# EXIT NONZERO "
#define COREDUMP_BUILD_ID_HEX_LEN 40
#define COREDUMP_BUILD_ID_BUF_LEN (COREDUMP_BUILD_ID_HEX_LEN + 1)

struct coredump_frame_info {
	bool has_pc;
	bool has_build_id;
	uint64_t pc;
	char path[PATH_MAX];
	char build_id[COREDUMP_BUILD_ID_BUF_LEN];
};

struct coredump_path_resolution {
	char recorded[PATH_MAX];
	char stripped[PATH_MAX];
	char proc_root[PATH_MAX];
	char cgroup_root[PATH_MAX];
	char cgroup_path[PATH_MAX];
	char native_selected[PATH_MAX];
	char debug_tried[PATH_MAX];
	char debug_selected[PATH_MAX];
	unsigned long cgroup_id;
	pid_t cgroup_pid;
	bool cgroup_found;
	bool cgroup_used;
};

struct coredump_file_handle {
	unsigned int handle_bytes;
	int handle_type;
	unsigned long cgroup_id;
};

struct coredump_cgroup_root {
	unsigned long cgroup_id;
	pid_t pid;
	char root[PATH_MAX];
	char path[PATH_MAX];
};

extern int name_to_handle_at(int dirfd, const char *pathname,
			     struct coredump_file_handle *handle,
			     int *mnt_id, int flags);


static struct ids_hash *record_map_ids(const struct cli_stackmap_record_map *map, uint32_t id)
{
	struct ids_hash *ids = NULL;

	HASH_FIND_INT(map->ids, &id, ids);
	return ids;
}

static struct str_hash *record_map_str(const struct cli_stackmap_record_map *map, uint32_t id)
{
	struct str_hash *str = NULL;

	HASH_FIND_INT(map->str, &id, str);
	return str;
}

static void format_record_time(uint64_t milliseconds, char *buffer)
{
	const uint64_t total_seconds = milliseconds / 1000;
	const int ms = milliseconds % 1000;

	const int hours = (total_seconds / 3600) % 24;
	const int minutes = (total_seconds / 60) % 60;
	const int seconds = total_seconds % 60;

	snprintf(buffer, 16, "%02d:%02d:%02d.%03d", hours, minutes, seconds, ms);
}

static bool tool_in_path(const char *tool)
{
	if (!tool || !tool[0])
		return false;

	if (strchr(tool, '/'))
		return access(tool, X_OK) == 0;

	const char *path_env = getenv("PATH");
	if (!path_env || !path_env[0])
		return false;

	char *path_dup = strdup(path_env);
	if (!path_dup)
		return false;

	bool found = false;
	char *saveptr = NULL;
	char *dir = strtok_r(path_dup, ":", &saveptr);
	while (dir) {
		char candidate[PATH_MAX];

		snprintf(candidate, sizeof(candidate), "%s/%s", dir, tool);
		if (access(candidate, X_OK) == 0) {
			found = true;
			break;
		}
		dir = strtok_r(NULL, ":", &saveptr);
	}

	free(path_dup);
	return found;
}

static const char *get_addr2line_tool(void)
{
	const char *tool = getenv(CPA_ADDR2LINE_ENV);

	if (tool && tool[0])
		return tool;

	return "addr2line";
}

static bool arg_is_null(const char *arg)
{
	return !arg || !arg[0] || strcmp(arg, "null") == 0;
}

static const char *get_core_debug_dirs(void *ctx)
{
	const char *debug_dirs = get_arg_by_name(ctx, "core_debug_dir");

	if (!arg_is_null(debug_dirs))
		return debug_dirs;

	debug_dirs = getenv(CPA_CORE_DEBUG_DIR_ENV);
	if (!arg_is_null(debug_dirs))
		return debug_dirs;

	return NULL;
}

static bool is_hex_string(const char *str, size_t len)
{
	if (!str)
		return false;

	for (size_t i = 0; i < len; i++) {
		if (!isxdigit((unsigned char)str[i]))
			return false;
	}

	return true;
}

/* The first frame of @ids that starts with @prefix, or NULL. */
static const char *stack_ids_find_marker(const struct cli_stackmap_record_map *map,
					 const struct ids_hash *ids,
					 const char *prefix)
{
	for (int i = 1; ids && i < ids->ids_len; i++) {
		struct str_hash *str = record_map_str(map, ids->ids[i]);

		if (str && strncmp(str->str, prefix, strlen(prefix)) == 0)
			return str->str;
	}

	return NULL;
}

static bool parse_coredump_native_frame(const char *frame,
					struct coredump_frame_info *info)
{
	const char *path_start, *path_end, *pc_start, *abs_pc_start;
	const char *build_id_start;
	size_t path_len;

	if (!frame || !info)
		return false;

	memset(info, 0, sizeof(*info));

	path_end = strrchr(frame, ']');
	if (!path_end || path_end == frame)
		return false;

	path_start = path_end;
	while (path_start > frame && *path_start != '[')
		path_start--;
	if (*path_start != '[')
		return false;

	path_start++;
	path_len = (size_t)(path_end - path_start);
	if (path_len == 0 || path_len >= sizeof(info->path))
		return false;

	memcpy(info->path, path_start, path_len);
	info->path[path_len] = '\0';

	if (strcmp(info->path, "anon exec segment") == 0 || info->path[0] != '/')
		return false;

	build_id_start = strstr(frame, "[build-id=");
	if (build_id_start) {
		const char *build_id_end;
		size_t build_id_len;

		build_id_start += strlen("[build-id=");
		build_id_end = strchr(build_id_start, ']');
		if (build_id_end) {
			build_id_len = (size_t)(build_id_end - build_id_start);
			if (build_id_len == COREDUMP_BUILD_ID_HEX_LEN &&
			    is_hex_string(build_id_start, build_id_len)) {
				memcpy(info->build_id, build_id_start,
				       build_id_len);
				info->build_id[build_id_len] = '\0';
				info->has_build_id = true;
			}
		}
	}

	pc_start = strstr(frame, "[pc=0x");
	if (pc_start) {
		info->pc = strtoull(pc_start + strlen("[pc=0x"), NULL, 16);
		info->has_pc = true;
		return true;
	}

	abs_pc_start = strstr(frame, " @0x");
	if (abs_pc_start) {
		info->pc = strtoull(abs_pc_start + strlen(" @0x"), NULL, 16);
		info->has_pc = true;
		return true;
	}

	if (strncmp(frame, "0x", 2) == 0) {
		info->pc = strtoull(frame + 2, NULL, 16);
		info->has_pc = true;
		return true;
	}

	return true;
}

static void join_root_path(char out[PATH_MAX], const char *root,
			   const char *path)
{
	if (!root || !path) {
		out[0] = '\0';
		return;
	}

	snprintf(out, PATH_MAX, "%s%s", root, path);
}

static bool parse_cgroup_root_hint(unsigned long cgroup_id,
				   struct coredump_cgroup_root *root)
{
	/*
	 * Test-only escape hatch used by offline list-core tests. Production
	 * lookup goes through name_to_handle_at() against the mounted cgroup
	 * tree below so the C and Rust resolvers exercise the same shape:
	 * cgroup id -> cgroup directory -> live peer pid -> /proc/<pid>/root.
	 */
	const char *hint = getenv(CPA_CORE_CGROUP_ROOT_HINT_ENV);
	char *copy = NULL;
	char *eq = NULL;
	char *pid_s = NULL;
	char *root_s = NULL;
	char *path_s = NULL;
	char *saveptr = NULL;
	unsigned long hint_id;
	char *end = NULL;

	if (!hint || !hint[0] || !root || cgroup_id == 0)
		return false;

	copy = strdup(hint);
	if (!copy)
		return false;

	eq = strchr(copy, '=');
	if (!eq)
		goto out;
	*eq = '\0';
	hint_id = strtoul(copy, &end, 10);
	if (!end || *end != '\0' || hint_id != cgroup_id)
		goto out;

	pid_s = strtok_r(eq + 1, ":", &saveptr);
	root_s = strtok_r(NULL, ":", &saveptr);
	path_s = strtok_r(NULL, "", &saveptr);
	if (!pid_s || !root_s || !path_s)
		goto out;

	memset(root, 0, sizeof(*root));
	root->cgroup_id = cgroup_id;
	root->pid = (pid_t)strtol(pid_s, NULL, 10);
	snprintf(root->root, sizeof(root->root), "%s", root_s);
	snprintf(root->path, sizeof(root->path), "%s", path_s);
	free(copy);
	return true;

out:
	free(copy);
	return false;
}

static bool find_cgroup_mount(char mount_path[PATH_MAX])
{
	size_t count = 0;
	struct mount_info *info = read_mount_info(&count);
	const char *v2_path = NULL;
	bool found = false;

	if (!info)
		return false;

	for (size_t i = 0; i < count; i++) {
		if (strcmp(info[i].type, "cgroup") == 0 &&
		    strstr(info[i].path, "cpu") != NULL) {
			snprintf(mount_path, PATH_MAX, "%s", info[i].path);
			found = true;
			break;
		}
		if (strcmp(info[i].type, "cgroup2") == 0)
			v2_path = info[i].path;
	}

	if (!found && v2_path) {
		snprintf(mount_path, PATH_MAX, "%s", v2_path);
		found = true;
	}

	free_mount_info(info, count);
	return found;
}

static unsigned long cgroup_id_for_path(const char *path)
{
	struct coredump_file_handle handle = { 0 };
	int mount_id = 0;

	if (!path)
		return 0;

	handle.handle_bytes = sizeof(handle.cgroup_id);
	if (name_to_handle_at(AT_FDCWD, path, &handle, &mount_id,
			      AT_SYMLINK_FOLLOW) != 0 ||
	    handle.handle_bytes != sizeof(handle.cgroup_id))
		return 0;

	return handle.cgroup_id;
}

static bool cgroup_root_from_procs(const char *cgroup_dir,
				   struct coredump_cgroup_root *root)
{
	char procs_path[PATH_MAX];
	FILE *fp = NULL;
	long pid;

	if (!cgroup_dir || !root)
		return false;

	/*
	 * The crashing pid is usually gone by offline export time. A live peer
	 * in the same cgroup gives us an equivalent mount namespace root for
	 * resolving container-local ELF paths recorded in the crash sample.
	 */
	snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", cgroup_dir);
	fp = fopen(procs_path, "r");
	if (!fp)
		return false;

	while (fscanf(fp, "%ld", &pid) == 1) {
		char proc_root[PATH_MAX];

		if (pid <= 0)
			continue;
		snprintf(proc_root, sizeof(proc_root), "/proc/%ld/root", pid);
		if (access(proc_root, F_OK) == 0) {
			root->pid = (pid_t)pid;
			snprintf(root->root, sizeof(root->root), "%s",
				 proc_root);
			fclose(fp);
			return true;
		}
	}

	fclose(fp);
	return false;
}

static bool find_cgroup_root_in_dir(const char *mount_path, const char *rel_path,
				    unsigned long cgroup_id, int depth,
				    struct coredump_cgroup_root *root)
{
	char full_path[PATH_MAX];
	DIR *dir = NULL;
	struct dirent *entry = NULL;

	if (depth > 128 || !mount_path || !rel_path || !root)
		return false;

	if (rel_path[0])
		snprintf(full_path, sizeof(full_path), "%s/%s", mount_path,
			 rel_path);
	else
		snprintf(full_path, sizeof(full_path), "%s", mount_path);

	if (cgroup_id_for_path(full_path) == cgroup_id) {
		memset(root, 0, sizeof(*root));
		root->cgroup_id = cgroup_id;
		snprintf(root->path, sizeof(root->path), "/%s", rel_path);
		if (strcmp(root->path, "/") == 0 || root->path[1] == '\0')
			snprintf(root->path, sizeof(root->path), "/");
		if (cgroup_root_from_procs(full_path, root))
			return true;
		return false;
	}

	dir = opendir(full_path);
	if (!dir)
		return false;

	while ((entry = readdir(dir)) != NULL) {
		char child_rel[PATH_MAX];
		char child_full[PATH_MAX];
		struct stat st;

		if (strcmp(entry->d_name, ".") == 0 ||
		    strcmp(entry->d_name, "..") == 0)
			continue;
		if (rel_path[0])
			snprintf(child_rel, sizeof(child_rel), "%s/%s",
				 rel_path, entry->d_name);
		else
			snprintf(child_rel, sizeof(child_rel), "%s",
				 entry->d_name);
		snprintf(child_full, sizeof(child_full), "%s/%s", mount_path,
			 child_rel);
		if (stat(child_full, &st) != 0 || !S_ISDIR(st.st_mode))
			continue;
		if (find_cgroup_root_in_dir(mount_path, child_rel, cgroup_id,
					    depth + 1, root)) {
			closedir(dir);
			return true;
		}
	}

	closedir(dir);
	return false;
}

static bool find_cgroup_root_by_id(unsigned long cgroup_id,
				   struct coredump_cgroup_root *root)
{
	char mount_path[PATH_MAX];

	if (!root || cgroup_id == 0)
		return false;

	if (parse_cgroup_root_hint(cgroup_id, root))
		return true;

	if (!find_cgroup_mount(mount_path))
		return false;

	return find_cgroup_root_in_dir(mount_path, "", cgroup_id, 0, root);
}

static const char *resolve_coredump_path(const char *path, pid_t container_pid,
					 unsigned long cgroup_id,
					 struct coredump_path_resolution *resolution)
{
	const char *container_path = path;
	bool stripped_proc_root = false;
	struct coredump_cgroup_root cgroup_root = { 0 };
	char cgroup_candidate[PATH_MAX] = { 0 };

	if (!path || !resolution)
		return NULL;

	memset(resolution, 0, sizeof(*resolution));
	snprintf(resolution->recorded, sizeof(resolution->recorded), "%s", path);

	/*
	 * Core dump frames can be recorded while the crashing task still has a
	 * live /proc/<pid>/root path. Offline list-core runs after that pid is
	 * gone, so a caller-provided container pid must replace the stale proc
	 * root prefix instead of being prepended on top of it.
	 *
	 * Keep the no-container recovery order aligned with the Rust TUI
	 * coredump resolver:
	 * 1. Prefer the recorded path when it still exists.
	 * 2. For a stale /proc/<crashed-pid>/root path, strip that prefix and
	 *    retry the container/host absolute path.
	 */
	if (strncmp(path, "/proc/", strlen("/proc/")) == 0) {
		const char *p = path + strlen("/proc/");
		const char *pid_start = p;

		while (isdigit((unsigned char)*p))
			p++;
		if (p != pid_start &&
		    strncmp(p, "/root", strlen("/root")) == 0 &&
		    (p[strlen("/root")] == '/' || p[strlen("/root")] == '\0')) {
			container_path = p + strlen("/root");
			if (container_path[0] == '\0')
				container_path = "/";
			stripped_proc_root = true;
		}
	}
	snprintf(resolution->stripped, sizeof(resolution->stripped), "%s",
		 container_path);

	/*
	 * If the user provides a live container pid, resolve through that root
	 * first. This is the most precise offline replacement for a stale
	 * /proc/<crashed-pid>/root prefix recorded at crash time.
	 */
	if (container_pid > 0 && path[0] == '/') {
		snprintf(resolution->proc_root, sizeof(resolution->proc_root),
			 "/proc/%d/root%s", container_pid,
			 container_path);
		if (access(resolution->proc_root, R_OK) == 0) {
			snprintf(resolution->native_selected,
				 sizeof(resolution->native_selected), "%s",
				 resolution->proc_root);
			return resolution->native_selected;
		}
	}

	if (container_pid <= 0 && find_cgroup_root_by_id(cgroup_id,
							 &cgroup_root)) {
		resolution->cgroup_found = true;
		resolution->cgroup_id = cgroup_root.cgroup_id;
		resolution->cgroup_pid = cgroup_root.pid;
		snprintf(resolution->cgroup_root,
			 sizeof(resolution->cgroup_root), "%s",
			 cgroup_root.root);
		snprintf(resolution->cgroup_path,
			 sizeof(resolution->cgroup_path), "%s",
			 cgroup_root.path);
		join_root_path(cgroup_candidate, cgroup_root.root,
			       container_path);
		if (access(cgroup_candidate, R_OK) == 0) {
			resolution->cgroup_used = true;
			snprintf(resolution->native_selected,
				 sizeof(resolution->native_selected), "%s",
				 cgroup_candidate);
			return resolution->native_selected;
		}
	}

	/*
	 * Without a live container pid, keep normal paths unchanged. For stale
	 * proc-root paths, fall back to the stripped absolute path so local
	 * reproductions like /proc/<dead>/root/root/app/lib.so can still resolve
	 * as /root/app/lib.so.
	 */
	if (access(path, R_OK) == 0) {
		snprintf(resolution->native_selected,
			 sizeof(resolution->native_selected), "%s", path);
		return resolution->native_selected;
	}
	if (stripped_proc_root && access(container_path, R_OK) == 0) {
		snprintf(resolution->native_selected,
			 sizeof(resolution->native_selected), "%s",
			 container_path);
		return resolution->native_selected;
	}

	snprintf(resolution->native_selected, sizeof(resolution->native_selected),
		 "%s", path);
	return resolution->native_selected;
}

static int run_addr2line(const char *tool, const char *elf_path, uint64_t pc,
			 char *output, size_t output_size)
{
	int pipefd[2];
	pid_t pid;
	ssize_t nread;
	int status = 0;
	char pc_arg[32];

	if (!tool || !elf_path || !output || output_size == 0)
		return -1;

	if (pipe(pipefd) != 0)
		return -1;

	snprintf(pc_arg, sizeof(pc_arg), "0x%llx", (unsigned long long)pc);
	pid = fork();
	if (pid == 0) {
		dup2(pipefd[1], STDOUT_FILENO);
		dup2(pipefd[1], STDERR_FILENO);
		close(pipefd[0]);
		close(pipefd[1]);
		execlp(tool, tool, "-C", "-f", "-e", elf_path, pc_arg, (char *)NULL);
		_exit(127);
	}

	close(pipefd[1]);
	if (pid < 0) {
		close(pipefd[0]);
		return -1;
	}

	nread = read(pipefd[0], output, output_size - 1);
	close(pipefd[0]);
	if (nread < 0)
		nread = 0;
	output[nread] = '\0';

	if (waitpid(pid, &status, 0) < 0)
		return -1;

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return -1;

	return 0;
}

static bool addr2line_output_has_source(const char *text)
{
	char *dup = NULL, *saveptr = NULL, *line = NULL;
	const char *source = NULL;
	int non_empty = 0;
	bool useful = false;

	if (!text || !text[0])
		return false;

	dup = strdup(text);
	if (!dup)
		return false;

	line = strtok_r(dup, "\n", &saveptr);
	while (line) {
		if (line[0]) {
			non_empty++;
			if (non_empty == 2) {
				source = line;
				break;
			}
		}
		line = strtok_r(NULL, "\n", &saveptr);
	}

	if (source && strncmp(source, "??:", strlen("??:")) != 0)
		useful = true;

	free(dup);
	return useful;
}

static bool try_debug_file_candidate(const char *candidate,
				     struct coredump_path_resolution *resolution,
				     char selected[PATH_MAX])
{
	if (!candidate || !resolution || !selected)
		return false;

	snprintf(resolution->debug_tried, sizeof(resolution->debug_tried),
		 "%s", candidate);
	if (access(candidate, R_OK) != 0)
		return false;

	snprintf(resolution->debug_selected, sizeof(resolution->debug_selected),
		 "%s", candidate);
	snprintf(selected, PATH_MAX, "%s", candidate);
	return true;
}

static bool build_debug_file_path(const char *root, const char *build_id,
				  char candidate[PATH_MAX])
{
	const char *slash = "";
	const char *debug_root = root;

	if (!root || !root[0] || !build_id || !candidate)
		return false;

	if (root[strlen(root) - 1] != '/')
		slash = "/";

	snprintf(candidate, PATH_MAX, "%s%s.build-id/%.2s/%s.debug",
		 debug_root, slash, build_id, build_id + 2);
	return true;
}

static bool find_build_id_debug_file(const struct coredump_frame_info *frame,
				     pid_t container_pid,
				     const char *debug_dirs,
				     struct coredump_path_resolution *resolution,
				     char selected[PATH_MAX])
{
	char candidate[PATH_MAX];
	char proc_debug_root[PATH_MAX];

	if (!frame || !frame->has_build_id || !resolution || !selected)
		return false;

	if (!is_hex_string(frame->build_id, COREDUMP_BUILD_ID_HEX_LEN))
		return false;

	if (build_debug_file_path("/usr/lib/debug", frame->build_id,
				  candidate) &&
	    try_debug_file_candidate(candidate, resolution, selected))
		return true;

	if (container_pid > 0) {
		snprintf(proc_debug_root, sizeof(proc_debug_root),
			 "/proc/%d/root/usr/lib/debug", container_pid);
		if (build_debug_file_path(proc_debug_root, frame->build_id,
					  candidate) &&
		    try_debug_file_candidate(candidate, resolution, selected))
			return true;
	}

	if (!arg_is_null(debug_dirs)) {
		char *dirs = strdup(debug_dirs);
		char *saveptr = NULL;
		char *dir = NULL;

		if (!dirs)
			return false;

		dir = strtok_r(dirs, ":", &saveptr);
		while (dir) {
			if (dir[0] &&
			    build_debug_file_path(dir, frame->build_id,
						  candidate) &&
			    try_debug_file_candidate(candidate, resolution,
						     selected)) {
				free(dirs);
				return true;
			}
			dir = strtok_r(NULL, ":", &saveptr);
		}
		free(dirs);
	}

	return false;
}

static void print_addr2line_inline(FILE *fp, const char *text,
				   const struct coredump_frame_info *frame,
				   const char *native_path,
				   const char *addr2line_path,
				   const struct coredump_path_resolution *resolution)
{
	char *dup = NULL, *saveptr = NULL, *line = NULL;
	const char *function = NULL;
	const char *source = NULL;

	if (!fp || !text || !text[0])
		return;

	dup = strdup(text);
	if (!dup)
		return;

	line = strtok_r(dup, "\n", &saveptr);
	while (line) {
		if (line[0]) {
			if (!function)
				function = line;
			else if (!source)
				source = line;
		}
		line = strtok_r(NULL, "\n", &saveptr);
	}

	if (function)
		fprintf(fp, "      Function   : %s\n", function);
	if (source)
		fprintf(fp, "      Source     : %s\n", source);
	fprintf(fp, "      Build ID   : %s\n",
		frame && frame->has_build_id ? frame->build_id : "(none)");
	fprintf(fp, "      Native Path: %s\n", native_path);
	fprintf(fp, "      Debug File : %s\n",
		resolution && resolution->debug_selected[0] ?
			resolution->debug_selected :
			"(not used)");
	if (resolution) {
		fprintf(fp, "      Path Resolution:\n");
		fprintf(fp, "        Recorded   : %s\n", resolution->recorded);
		fprintf(fp, "        Stripped   : %s\n", resolution->stripped);
		fprintf(fp, "        Proc Root  : %s\n",
			resolution->proc_root[0] ? resolution->proc_root :
							"(none)");
		if (resolution->cgroup_found) {
			fprintf(fp,
				"        CGroup Root: %s (cgroup_id=%lu path=%s pid=%d)\n",
				resolution->cgroup_root, resolution->cgroup_id,
				resolution->cgroup_path, resolution->cgroup_pid);
		}
		fprintf(fp, "        Debug Tried: %s\n",
			resolution->debug_tried[0] ? resolution->debug_tried :
							"(none)");
		fprintf(fp, "        Selected   : %s\n",
			addr2line_path ? addr2line_path :
			resolution->native_selected);
	}

	free(dup);
}

static void print_coredump_metadata(FILE *fp, const struct metadata *data,
				    const char *raw, bool parsed)
{
	fprintf(fp, "MetaData:\n");
	if (!parsed) {
		fprintf(fp, "  Parse      : failed\n");
		fprintf(fp, "  Raw        : %s\n", raw);
		return;
	}

	fprintf(fp, "  Thread     : %s\n", data->comm);
	fprintf(fp, "  Process    : %s\n", data->group_comm);
	fprintf(fp, "  PID        : %u\n", data->pid);
	fprintf(fp, "  CPU        : %d\n", data->cpu);
	fprintf(fp, "  CGroup ID  : %lu\n", data->cg_id);
	fprintf(fp, "  Env        : %s\n", data->env);
	fprintf(fp, "  Raw        : %s\n", data->raw);
}

/*
 * What --list-core and --list-exit list: the records carrying one marker.
 * Both are written by the same sidecar path in the same verbose frame
 * format, so everything else, --core-verbose included, is shared.
 */
struct list_kind {
	const char *marker;
	const char *name;	/* "CoreDump": titles */
	const char *noun;	/* "coredump": messages */
	const char *file;	/* default output file prefix */
};

static const struct list_kind list_core_kind = {
	COREDUMP_MARKER_PREFIX, "CoreDump", "coredump", "cpa_core",
};

static const struct list_kind list_exit_kind = {
	EXIT_MARKER_PREFIX, "Exit", "exit", "cpa_exit",
};

/* "<# EXIT NONZERO raw=768 exit=3 #>" with @prefix "<# EXIT NONZERO ": "raw=768 exit=3" */
static void print_marker_body(FILE *fp, const char *label, const char *frame,
			      const char *prefix)
{
	const char *body = frame + strlen(prefix);
	size_t len = strlen(body);

	if (len >= 3 && strcmp(body + len - 3, " #>") == 0)
		len -= 3;
	fprintf(fp, "  %-11s: %.*s\n", label, (int)len, body);
}

int cpa_show_list(void *ctx, bool exits,
		  bool (*filter_func)(struct metadata *data),
				      const char *read_file,
				      struct cli_stackmap_record_map *map,
				      struct stackmap_record *record,
				      int output_num,
				      uint64_t starttime,
				      pid_t container_pid)
{
	const struct list_kind *kind = exits ? &list_exit_kind : &list_core_kind;
	const char *output_prof = get_arg_by_name(ctx, "output_prof");
	const char *addr2line_tool = get_addr2line_tool();
	const char *core_debug_dirs = get_core_debug_dirs(ctx);
	bool core_verbose = atoi(get_arg_by_name(ctx, "core_verbose")) != 0;
	char output_prof_path[PATH_MAX] = {0};
	FILE *fp = NULL;
	int total_matches = 0;

	if (!output_prof || strncmp(output_prof, "null", strlen("null")) == 0) {
		snprintf(output_prof_path, PATH_MAX, "%s_%s_%d.txt", kind->file,
			 convert_millisecond_to_time(starttime), output_num);
		output_prof = output_prof_path;
	}

	if (core_verbose && !tool_in_path(addr2line_tool)) {
		CLI_ERROR("addr2line not found. Set %s to override the tool path.",
			  CPA_ADDR2LINE_ENV);
		return -1;
	}

	fp = fopen(output_prof, "w");
	if (!fp) {
		CLI_ERROR("Open %s Failed", output_prof);
		return -1;
	}

	fprintf(fp, "%s Samples Export\n", kind->name);
	fprintf(fp, "Source: %s\n", read_file);
	fprintf(fp, "Verbose: %s\n", core_verbose ? "on" : "off");
	if (container_pid > 0)
		fprintf(fp, "Container PID: %d\n", container_pid);
	fprintf(fp, "\n");

	for (int record_offset = 0; record_offset < output_num; record_offset++) {
		struct stackmap_record *current_record = &record[record_offset];
		struct id_count *id_count_all =
			cli_stackmap_dump(read_file, current_record, 1);
		struct id_count *id_count = NULL;
		char start_buf[16] = {0};
		char end_buf[16] = {0};

		format_record_time(current_record->starttime, start_buf);
		format_record_time(current_record->endtime, end_buf);

		FOR_EACH_ID_COUNT_SORT_BY_COUNT(id_count_all, id_count)
		{
			struct ids_hash *ids =
				record_map_ids(map, id_count->ids_id);
			struct str_hash *meta_str = NULL;
			struct metadata data = { 0 };
			const char *marker = NULL;
			bool parsed = false;

			if (!ids || ids->ids_len == 0 ||
			    !(marker = stack_ids_find_marker(map, ids, kind->marker)))
				continue;

			meta_str = record_map_str(map, ids->ids[0]);
			if (!meta_str)
				continue;

			parsed = parse_metadata(meta_str->str, &data) == 0;
			if (parsed && filter_func(&data))
				continue;

			total_matches++;
			fprintf(fp, "========== %s Sample %d ==========\n",
				kind->name, total_matches);
			fprintf(fp, "Time Window : %s - %s\n", start_buf, end_buf);
			fprintf(fp, "Count       : %lu\n", id_count->count);
			print_coredump_metadata(fp, &data, meta_str->str, parsed);
			if (kind == &list_exit_kind)
				print_marker_body(fp, "Exit", marker,
						  EXIT_MARKER_PREFIX);
			fprintf(fp, "Frames:\n");

			for (int frame_index = 1; frame_index < ids->ids_len;
			     frame_index++) {
				struct str_hash *frame_str =
					record_map_str(map, ids->ids[frame_index]);
				struct coredump_frame_info frame_info;

				if (!frame_str)
					continue;

				fprintf(fp, "  [%02d] %s\n", frame_index - 1,
					frame_str->str);

				if (core_verbose &&
				    parse_coredump_native_frame(frame_str->str,
								&frame_info)) {
					struct coredump_path_resolution resolution;
					char native_addr2line_buf[4096] = {0};
					char debug_addr2line_buf[4096] = {0};
					char debug_path[PATH_MAX] = {0};
					const char *path = NULL;
					const char *addr2line_path = NULL;
					const char *addr2line_output = NULL;
					bool native_ran = false;
					bool native_useful = false;

					path = resolve_coredump_path(frame_info.path,
								 container_pid,
								 data.cg_id,
								 &resolution);
					if (!frame_info.has_pc || !path)
						continue;

					if (access(path, R_OK) == 0 &&
					    run_addr2line(addr2line_tool, path,
							  frame_info.pc,
							  native_addr2line_buf,
							  sizeof(native_addr2line_buf)) == 0) {
						native_ran = true;
						native_useful =
							addr2line_output_has_source(
								native_addr2line_buf);
					}

					if (native_useful) {
						addr2line_path = path;
						addr2line_output = native_addr2line_buf;
					} else if (find_build_id_debug_file(
							   &frame_info,
							   container_pid,
							   core_debug_dirs,
							   &resolution,
							   debug_path) &&
						   run_addr2line(addr2line_tool,
								 debug_path,
								 frame_info.pc,
								 debug_addr2line_buf,
								 sizeof(debug_addr2line_buf)) == 0) {
						addr2line_path = debug_path;
						addr2line_output = debug_addr2line_buf;
					} else if (native_ran) {
						addr2line_path = path;
						addr2line_output = native_addr2line_buf;
					}

					if (!addr2line_output) {
						fprintf(fp,
							"      addr2line skipped for %s (pc=0x%llx)\n",
							path,
							(unsigned long long)frame_info.pc);
						continue;
					}

					print_addr2line_inline(fp,
							       addr2line_output,
							       &frame_info,
							       path,
							       addr2line_path,
							       &resolution);
				}
			}

			fprintf(fp, "\n");
		}

		cli_stackmap_dump_free(id_count_all);
	}

	if (total_matches == 0)
		fprintf(fp, "No %s samples found in selected range.\n", kind->noun);

	fclose(fp);
	CLI_OUTPUT("Write %s records to %s, samples=%d", kind->noun, output_prof,
		   total_matches);
	return 0;
}
