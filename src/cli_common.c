// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "cli.h"

static bool bpf_inited;

int init_module_bpf(void *ctx, int module)
{
	struct cpa_bpf_init_options options = { 0 };

	if (atoi(get_arg_by_name(ctx, "verbose")))
		set_cpa_bpf_verbose();

	if (bpf_inited) {
		if (bpf_module_ctl(get_bpf_mask() | (1UL << module))) {
			CLI_ERROR("BPF init failed.\n");
			return -1;
		}
	} else {
		options.mask = 1UL << module;
		options.btf_path = get_arg_by_name(ctx, "btf_path");
		if (init_bpf(&options)) {
			CLI_ERROR("BPF init failed.\n");
			return -1;
		}
		bpf_inited = true;
	}

	if (!(get_bpf_mask() & 1UL << module)) {
		CLI_ERROR("BPF_MODULE init failed.\n");
		return -1;
	}

	return 0;
}

static volatile sig_atomic_t g_stop_flag;

/*
 * Signal handlers only set this async-signal-safe flag. Runtime, timer, and
 * unwinder loops observe it at their own safe points.
 */
int should_stop(void)
{
	return g_stop_flag;
}

void set_stop(void)
{
	g_stop_flag = true;
}

char *read_file_content(const char *path)
{
	FILE *file = fopen(path, "r");
	if (file == NULL) {
		return NULL;
	}
	size_t buffer_size = 1024;
	char *data = (char *)malloc(buffer_size);
	if (data == NULL) {
		CLI_ERROR("Failed to malloc");
		fclose(file);
		return NULL;
	}

	size_t total_read = 0;
	size_t read_size;
	while ((read_size = fread(data + total_read, 1, buffer_size - total_read - 1, file)) > 0) {
		total_read += read_size;
		if (total_read >= buffer_size - 1) {
			buffer_size *= 2;
			char *new_data = (char *)realloc(data, buffer_size);
			if (new_data == NULL) {
				CLI_ERROR("Failed to realloc");
				free(data);
				fclose(file);
				return NULL;
			}
			data = new_data;
		}
	}

	data[total_read] = '\0';
	fclose(file);

	return data;
}

void free_mount_info(struct mount_info *mounts, size_t count)
{
	for (size_t i = 0; i < count; i++) {
		free(mounts[i].path);
		free(mounts[i].type);
	}
	free(mounts);
}

struct mount_info *read_mount_info(size_t *count)
{
	FILE *file = fopen("/proc/self/mountinfo", "r");
	if (!file) {
		perror("Failed to open /proc/self/mountinfo");
		return NULL;
	}

	size_t capacity = 10;
	struct mount_info *mounts = malloc(capacity * sizeof(struct mount_info));
	if (!mounts) {
		CLI_ERROR("Failed to allocate memory");
		fclose(file);
		return NULL;
	}

	char line[1024];
	*count = 0;

	while (fgets(line, sizeof(line), file)) {
		if (*count >= capacity) {
			capacity *= 2;
			struct mount_info *new_mounts = realloc(mounts, capacity * sizeof(struct mount_info));
			if (!new_mounts) {
				perror("Failed to allocate memory");
				free_mount_info(mounts, *count);
				fclose(file);
				return NULL;
			}
			mounts = new_mounts;
		}

		char *token = strtok(line, " ");
		for (int i = 0; i < 3; i++) {
			if (!token)
				break;
			token = strtok(NULL, " ");
		}
		if (!token)
			continue;

		token = strtok(NULL, " ");
		if (!token)
			continue;

		mounts[*count].path = malloc(strlen(token) + 1);
		if (!mounts[*count].path) {
			perror("Failed to allocate memory");
			free_mount_info(mounts, *count);
			fclose(file);
			return NULL;
		}
		strcpy(mounts[*count].path, token);

		for (int i = 0; i < 3; i++) {
			token = strtok(NULL, " ");
			if (!token)
				break;
		}
		if (!token || strcmp(token, "-") != 0) {
			free(mounts[*count].path);
			continue;
		}

		token = strtok(NULL, " ");
		if (!token) {
			free(mounts[*count].path);
			continue;
		}

		mounts[*count].type = malloc(strlen(token) + 1);
		if (!mounts[*count].type) {
			CLI_ERROR("Failed to allocate memory");
			free(mounts[*count].path);
			free_mount_info(mounts, *count);
			fclose(file);
			return NULL;
		}
		strcpy(mounts[*count].type, token);

		(*count)++;
	}

	fclose(file);

	return mounts;
}

void traverse_proc_smaps(void (*smaps_read)(pid_t pid, char *smaps, void *ctx), void *ctx)
{
	struct dirent *entry;
	DIR *dp = opendir("/proc");
	if (!dp) {
		perror("Failed to open /proc");
		return;
	}

	while ((entry = readdir(dp)) != NULL) {
		if (entry->d_type == DT_DIR && isdigit(entry->d_name[0])) {
			char smaps_path[256];
			snprintf(smaps_path, sizeof(smaps_path), "/proc/%s/smaps", entry->d_name);
			pid_t pid = atoi(entry->d_name);
			char *content = read_file_content(smaps_path);
			if (content) {
				smaps_read(pid, content, ctx);
				free(content);
			}
		}
	}

	closedir(dp);
}

int get_pid_stat(pid_t pid, struct pid_stat *stat, unsigned int flags)
{
	char path[128] = { 0 };
	FILE *fp = NULL;
	char buffer[1024] = { 0 };
	int need_state = 0;
	int need_start_time = 0;
	int need_cpu_id = 0;
	int ret = 0;

	if (!stat)
		return -1;

	memset(stat->comm, 0, sizeof(stat->comm));
	stat->start_time = 0;
	stat->state = 0;
	stat->cpu_id = 0;
	stat->valid_mask = 0;

	need_state = !!(flags & PID_STAT_F_STATE);
	need_start_time = !!(flags & PID_STAT_F_START_TIME);
	need_cpu_id = !!(flags & PID_STAT_F_CPU_ID);

	ret = snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	if (ret < 0 || ret >= (int)sizeof(path)) {
		snprintf(stat->comm, TASK_COMM_LEN, "<err read stat>");
		return -1;
	}

	fp = fopen(path, "r");
	if (!fp) {
		if (errno == ENOENT)
			snprintf(stat->comm, TASK_COMM_LEN, "<exit task>");
		else
			snprintf(stat->comm, TASK_COMM_LEN, "<err read stat>");
		return -1;
	}

	if (!fgets(buffer, sizeof(buffer), fp))
		goto err;

	fclose(fp);
	fp = NULL;

	char *start_paren = NULL;
	char *end_paren = NULL;
	size_t len = 0;

	start_paren = strchr(buffer, '(');
	end_paren = strrchr(buffer, ')');
	if (!start_paren || !end_paren || end_paren < start_paren)
		goto err;

	len = end_paren - start_paren - 1;
	if (len >= TASK_COMM_LEN)
		len = TASK_COMM_LEN - 1;
	memcpy(stat->comm, start_paren + 1, len);
	stat->comm[len] = '\0';

	char *p = NULL;
	char *saveptr = NULL;
	char *token = NULL;
	int field = 0;
	int target_field = 0;
	int have_state = 0;
	int have_start_time = 0;
	int have_cpu_id = 0;
	char state_val = 0;
	unsigned long long start_time_val = 0;
	int cpu_val = 0;

	p = end_paren + 2;
	token = strtok_r(p, " ", &saveptr);
	field = 3;
	target_field = 3;
	if (need_start_time)
		target_field = 22;
	if (need_cpu_id)
		target_field = 39;

	while (token) {
		if (field == 3) {
			state_val = token[0];
			have_state = 1;
		} else if (field == 22) {
			start_time_val = strtoull(token, NULL, 10);
			have_start_time = 1;
		} else if (field == 39) {
			cpu_val = atoi(token);
			have_cpu_id = 1;
		}
		if (field >= target_field)
			break;

		token = strtok_r(NULL, " ", &saveptr);
		field++;
	}

	if (need_state && !have_state)
		goto err;
	if (need_start_time && !have_start_time)
		goto err;

	if (need_state && have_state) {
		stat->state = state_val;
		stat->valid_mask |= PID_STAT_F_STATE;
	}
	if (need_start_time && have_start_time) {
		stat->start_time = start_time_val;
		stat->valid_mask |= PID_STAT_F_START_TIME;
	}
	if (need_cpu_id && have_cpu_id) {
		stat->cpu_id = (unsigned int)cpu_val;
		stat->valid_mask |= PID_STAT_F_CPU_ID;
	}

	return 0;

err:
	if (fp)
		fclose(fp);
	snprintf(stat->comm, TASK_COMM_LEN, "<err read stat>");
	return -1;
}

#define INITIAL_CAPACITY 10

struct smaps_desc *get_smaps_desc(char *smaps, size_t *count)
{
	size_t capacity = INITIAL_CAPACITY;
	struct smaps_desc *desc_array = malloc(capacity * sizeof(struct smaps_desc));
	if (!desc_array) {
		fprintf(stderr, "Memory allocation failed");
		return NULL;
	}

	*count = 0;
	char *pos = smaps;

	while (pos && *pos) {
		if (*count >= capacity) {
			capacity *= 2;
			struct smaps_desc *new_desc_array = realloc(desc_array, capacity * sizeof(struct smaps_desc));
			if (!new_desc_array) {
				fprintf(stderr, "Memory allocation failed");
				free(desc_array);
				return NULL;
			}
			desc_array = new_desc_array;
		}

		struct smaps_desc *desc = &desc_array[*count];
		memset(desc, 0, sizeof(struct smaps_desc));

		if (sscanf(pos, "%lx-%lx", &desc->start, &desc->end) != 2) {
			free(desc_array);
			return NULL;
		}

		const char *path_start = strstr(pos, "/");
		const char *path_end = path_start ? strstr(path_start, "\n") : NULL;
		if (path_start && path_end) {
			size_t path_len = path_end - path_start;
			desc->path = malloc(path_len + 1);
			if (!desc->path) {
				fprintf(stderr, "Memory allocation failed");
				free(desc_array);
				return NULL;
			}
			strncpy(desc->path, path_start, path_len);
			desc->path[path_len] = '\0';
		} else {
			desc->path = NULL;
		}

		pos = strchr(pos, '\n') + 1;

		while (pos && *pos) {
			if (sscanf(pos, "Size: %lu kB", &desc->size) == 1)
				goto next;
			if (sscanf(pos, "KernelPageSize: %lu kB", &desc->kernelpagesize) == 1)
				goto next;
			if (sscanf(pos, "MMUPageSize: %lu kB", &desc->mmupagesize) == 1)
				goto next;
			if (sscanf(pos, "Rss: %lu kB", &desc->rss) == 1)
				goto next;
			if (sscanf(pos, "Pss: %lu kB", &desc->pss) == 1)
				goto next;
			if (sscanf(pos, "Shared_Clean: %lu kB", &desc->shared_clean) == 1)
				goto next;
			if (sscanf(pos, "Shared_Dirty: %lu kB", &desc->shared_dirty) == 1)
				goto next;
			if (sscanf(pos, "Private_Clean: %lu kB", &desc->private_clean) == 1)
				goto next;
			if (sscanf(pos, "Private_Dirty: %lu kB", &desc->private_dirty) == 1)
				goto next;
			if (sscanf(pos, "Referenced: %lu kB", &desc->referenced) == 1)
				goto next;
			if (sscanf(pos, "Anonymous: %lu kB", &desc->anonymous) == 1)
				goto next;
			if (sscanf(pos, "LazyFree: %lu kB", &desc->lazyfree) == 1)
				goto next;
			if (sscanf(pos, "AnonHugePages: %lu kB", &desc->anonhugepages) == 1)
				goto next;
			if (sscanf(pos, "ShmemPmdMapped: %lu kB", &desc->shmem_pmdmapped) == 1)
				goto next;
			if (sscanf(pos, "FilePmdMapped: %lu kB", &desc->file_pmdmapped) == 1)
				goto next;
			if (sscanf(pos, "Shared_Hugetlb: %lu kB", &desc->shared_hugetlb) == 1)
				goto next;
			if (sscanf(pos, "Private_Hugetlb: %lu kB", &desc->private_hugetlb) == 1)
				goto next;
			if (sscanf(pos, "Swap: %lu kB", &desc->swap) == 1)
				goto next;
			if (sscanf(pos, "SwapPss: %lu kB", &desc->swap_pss) == 1)
				goto next;
			if (sscanf(pos, "Locked: %lu kB", &desc->locked) == 1)
				goto next;
			if (sscanf(pos, "THPeligible: %lu", &desc->thpeligible) == 1)
				goto next;
			if (sscanf(pos, "ProtectionKey: %lu", &desc->protectionkey) == 1)
				goto next;

			if (strncmp(pos, "VmFlags:", 8) == 0) {
				pos += 8;
				char *next_segment = strchr(pos, '\n');
				while (*pos != '\0' && *pos != '\n') {
					if (strncmp(pos, "rd", 2) == 0)
						desc->vmflags.rd = 1;
					else if (strncmp(pos, "wr", 2) == 0)
						desc->vmflags.wr = 1;
					else if (strncmp(pos, "ex", 2) == 0)
						desc->vmflags.ex = 1;
					else if (strncmp(pos, "sh", 2) == 0)
						desc->vmflags.sh = 1;
					else if (strncmp(pos, "mr", 2) == 0)
						desc->vmflags.mr = 1;
					else if (strncmp(pos, "mw", 2) == 0)
						desc->vmflags.mw = 1;
					else if (strncmp(pos, "me", 2) == 0)
						desc->vmflags.me = 1;
					else if (strncmp(pos, "ms", 2) == 0)
						desc->vmflags.ms = 1;
					else if (strncmp(pos, "gd", 2) == 0)
						desc->vmflags.gd = 1;
					else if (strncmp(pos, "pf", 2) == 0)
						desc->vmflags.pf = 1;
					else if (strncmp(pos, "dw", 2) == 0)
						desc->vmflags.dw = 1;
					else if (strncmp(pos, "lo", 2) == 0)
						desc->vmflags.lo = 1;
					else if (strncmp(pos, "io", 2) == 0)
						desc->vmflags.io = 1;
					else if (strncmp(pos, "sr", 2) == 0)
						desc->vmflags.sr = 1;
					else if (strncmp(pos, "rr", 2) == 0)
						desc->vmflags.rr = 1;
					else if (strncmp(pos, "dc", 2) == 0)
						desc->vmflags.dc = 1;
					else if (strncmp(pos, "de", 2) == 0)
						desc->vmflags.de = 1;
					else if (strncmp(pos, "ac", 2) == 0)
						desc->vmflags.ac = 1;
					else if (strncmp(pos, "nr", 2) == 0)
						desc->vmflags.nr = 1;
					else if (strncmp(pos, "ht", 2) == 0)
						desc->vmflags.ht = 1;
					else if (strncmp(pos, "ar", 2) == 0)
						desc->vmflags.ar = 1;
					else if (strncmp(pos, "dd", 2) == 0)
						desc->vmflags.dd = 1;
					else if (strncmp(pos, "sd", 2) == 0)
						desc->vmflags.sd = 1;
					else if (strncmp(pos, "mm", 2) == 0)
						desc->vmflags.mm = 1;
					else if (strncmp(pos, "hg", 2) == 0)
						desc->vmflags.hg = 1;
					else if (strncmp(pos, "nh", 2) == 0)
						desc->vmflags.nh = 1;
					else if (strncmp(pos, "mg", 2) == 0)
						desc->vmflags.mg = 1;

					while (*pos && *pos != ' ' && *pos != '\n')
						pos++;

					while (*pos == ' ')
						pos++;
				}
				pos = next_segment + 1;
				goto next_desc;
			}

		next:
			pos = strchr(pos, '\n');
			if (pos)
				pos++;
		}

	next_desc:

		(*count)++;
	}

	return desc_array;
}

void free_smaps_desc(struct smaps_desc *desc_array, size_t count)
{
	for (int i = 0; i < count; i++) {
		free(desc_array[i].path);
	}
	free(desc_array);
}

uint64_t get_start_of_today(void)
{
	time_t now = time(NULL);
	struct tm *now_tm = localtime(&now);

	now_tm->tm_hour = 0;
	now_tm->tm_min = 0;
	now_tm->tm_sec = 0;

	return (uint64_t)mktime(now_tm);
}

uint64_t convert_time_to_seconds(const char *time_str)
{
	if (!time_str || cli_arg_is_null_default(time_str)) {
		CLI_ERROR("Invalid time format\n");
		return UINT64_MAX;
	}

	int hours, minutes, seconds;

	if (sscanf(time_str, "%d:%d:%d", &hours, &minutes, &seconds) != 3) {
		CLI_ERROR("Invalid time format\n");
		return UINT64_MAX;
	}

	return hours * 3600 + minutes * 60 + seconds;
}

static char time_str[16];

const char *convert_millisecond_to_time(uint64_t millisecond)
{
	uint64_t seconds = millisecond / 1000;
	int milliseconds = millisecond % 1000;

	int hours = seconds / 3600;
	seconds %= 3600;
	int minutes = seconds / 60;
	seconds %= 60;
	int sec = (int)seconds;

	snprintf(time_str, sizeof(time_str), "%02d:%02d:%02d.%03d", hours, minutes, sec, milliseconds);
	return time_str;
}

static char *trim_trailing_whitespace(char *str)
{
	size_t len = strlen(str);
	while (len > 0 && (str[len - 1] == '\n' || str[len - 1] == ' ')) {
		str[len - 1] = '\0';
		len--;
	}
	return str;
}

char *path_join(const char *path1, const char *path2)
{
	if (!path1 || !path2) {
		return NULL;
	}

	size_t len1 = strlen(path1);
	size_t len2 = strlen(path2);

	int need_separator = (len1 > 0 && path1[len1 - 1] != '/' && path2[0] != '/') ? 1 : 0;

	size_t total_len = len1 + len2 + need_separator + 1;

	char *result = (char *)malloc(total_len);
	if (!result) {
		CLI_ERROR("Failed to allocate memory");
		return NULL;
	}

	strcpy(result, path1);

	if (need_separator) {
		result[len1] = '/';
		len1++;
	}

	strcpy(result + len1, path2);

	return trim_trailing_whitespace(result);
}

struct file_handle {
	unsigned int handle_bytes;
	int handle_type;
	unsigned long cgroup_id;
};

extern int name_to_handle_at(int dirfd, const char *pathname, struct file_handle *handle, int *mnt_id, int flags);

const char *cgroup_mount_path = NULL;

const char *get_cgroup_mount_path(void)
{
	if (cgroup_mount_path && access(cgroup_mount_path, F_OK) != -1)
		return cgroup_mount_path;

	free((void *)cgroup_mount_path);

	cgroup_mount_path = NULL;

	size_t count;
	struct mount_info *info = read_mount_info(&count);
	char *cgroup_mount_path_v2 = NULL;

	for (int i = 0; i < count; i++) {
		if (strcmp(info[i].type, "cgroup") == 0 && strstr(info[i].path, "cpu") != 0) {
			cgroup_mount_path = strdup(info[i].path);
			break;
		}

		if (strcmp(info[i].type, "cgroup2") == 0 && !cgroup_mount_path_v2)
			cgroup_mount_path_v2 = strdup(info[i].path);
	}

	free_mount_info(info, count);

	if (cgroup_mount_path) {
		free(cgroup_mount_path_v2);
		return cgroup_mount_path;
	} else if (cgroup_mount_path_v2) {
		cgroup_mount_path = cgroup_mount_path_v2;
		cgroup_mount_path_v2 = NULL;
	} else {
		CLI_ERROR("FATAL: Failed to find cgroup mount point");
	}

	if (!cgroup_mount_path && cgroup_mount_path_v2)
		CLI_ERROR("Failed to cache cgroup mount point");

	free(cgroup_mount_path_v2);
	return cgroup_mount_path;
}

unsigned long get_cgroup_id(const char *cgroup_path)
{
	int err;
	int mount_id;
	struct statfs fs;
	struct file_handle handle = {};

	if (!cgroup_mount_path)
		if (!get_cgroup_mount_path())
			return 0;

	char *cgroup_path_full = path_join(cgroup_mount_path, cgroup_path);

	err = statfs(cgroup_path_full, &fs);
	if (err) {
		free(cgroup_path_full);
		return 0;
	}

	handle.handle_bytes = 8;
	err = name_to_handle_at(AT_FDCWD, cgroup_path_full, (struct file_handle *)&handle, &mount_id, AT_SYMLINK_FOLLOW);
	if (err || handle.handle_bytes != 8) {
		CLI_ERROR("%s name_to_handle_at failed: %d %u\n", cgroup_path_full, errno, handle.handle_bytes);
		free(cgroup_path_full);
		return 0;
	}

	free(cgroup_path_full);
	return handle.cgroup_id;
}

long get_directory_size(const char *dir_path)
{
	DIR *dir = opendir(dir_path);
	if (dir == NULL) {
		CLI_ERROR("opendir %s failed!", dir_path);
		return -1;
	}

	struct dirent *entry;
	struct stat statbuf;
	long total_size = 0;

	while ((entry = readdir(dir)) != NULL) {
		char file_path[PATH_MAX];
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
			continue;
		}

		snprintf(file_path, sizeof(file_path), "%s/%s", dir_path, entry->d_name);

		if (stat(file_path, &statbuf) == -1) {
			CLI_ERROR("stat %s failed!", file_path);
			closedir(dir);
			return -1;
		}

		if (S_ISREG(statbuf.st_mode)) {
			total_size += statbuf.st_size;
		}
	}

	closedir(dir);
	return total_size;
}

int create_directory_if_notexist(const char *path)
{
	struct stat st = { 0 };
	if (stat(path, &st) == -1) {
		mkdir(path, 0700);
		if (stat(path, &st) == -1)
			return -1;
	}
	return 0;
}

int remove_directory(const char *path)
{
	DIR *d = opendir(path);
	size_t path_len = strlen(path);
	int r = -1;

	if (d) {
		struct dirent *p;

		r = 0;
		while (!r && (p = readdir(d))) {
			int r2 = -1;
			char *buf;
			size_t len;

			if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, ".."))
				continue;

			len = path_len + strlen(p->d_name) + 2;
			buf = malloc(len);

			if (buf) {
				struct stat statbuf;

				snprintf(buf, len, "%s/%s", path, p->d_name);
				if (!stat(buf, &statbuf)) {
					if (S_ISDIR(statbuf.st_mode))
						r2 = remove_directory(buf);
					else
						r2 = unlink(buf);
				}
				free(buf);
			}
			r = r2;
		}
		closedir(d);
	}

	if (!r)
		r = rmdir(path);

	return r;
}

#include <limits.h>

void set_cpu_in_bitmap(unsigned long *bitmap, int cpu)
{
	bitmap[cpu / (sizeof(unsigned long) * CHAR_BIT)] |= 1UL << (cpu % (sizeof(unsigned long) * CHAR_BIT));
}

bool is_cpu_in_bitmap(const unsigned long *bitmap, int cpu)
{
	return bitmap[cpu / (sizeof(unsigned long) * CHAR_BIT)] & (1UL << (cpu % (sizeof(unsigned long) * CHAR_BIT)));
}

struct cpu_set parse_cpu_set(const char *cpu_str)
{
	struct cpu_set set = { 0, NULL };
	if (!cpu_str)
		return set;

	int max_cpu = 0;
	const char *ptr = cpu_str;
	while (*ptr) {
		int start, end;
		if (sscanf(ptr, "%d-%d", &start, &end) == 2) {
			if (end > max_cpu)
				max_cpu = end;
			ptr = strchr(ptr, ',');
			if (!ptr)
				break;
			ptr++;
		} else if (sscanf(ptr, "%d", &start) == 1) {
			if (start > max_cpu)
				max_cpu = start;
			ptr = strchr(ptr, ',');
			if (!ptr)
				break;
			ptr++;
		} else {
			break;
		}
	}

	set.max_cpu = max_cpu + 1;
	size_t bitmap_size = (max_cpu + 1 + (sizeof(unsigned long) * CHAR_BIT - 1)) / (sizeof(unsigned long) * CHAR_BIT);
	set.bitmap = (unsigned long *)calloc(bitmap_size, sizeof(unsigned long));
	if (!set.bitmap)
		return set;

	ptr = cpu_str;
	while (*ptr) {
		int start, end;
		char *next;
		if (sscanf(ptr, "%d-%d", &start, &end) == 2) {
			for (int i = start; i <= end; i++) {
				set_cpu_in_bitmap(set.bitmap, i);
			}
			next = strchr(ptr, ',');
		} else if (sscanf(ptr, "%d", &start) == 1) {
			set_cpu_in_bitmap(set.bitmap, start);
			next = strchr(ptr, ',');
		} else {
			break;
		}
		if (!next)
			break;
		ptr = next + 1;
	}

	return set;
}

bool is_cpu_in_set(const struct cpu_set *set, int cpu_num)
{
	if (cpu_num < 0 || cpu_num >= set->max_cpu) {
		return false;
	}
	return is_cpu_in_bitmap(set->bitmap, cpu_num);
}

void free_cpu_set(struct cpu_set *set)
{
	if (set->bitmap) {
		free(set->bitmap);
	}
	set->bitmap = NULL;
	set->max_cpu = 0;
}

void get_self_rss_status(struct rss_status *status)
{
	FILE *file = fopen("/proc/self/status", "r");
	if (!file) {
		CLI_ERROR("fopen");
		return;
	}

	char line[256];
	while (fgets(line, sizeof(line), file)) {
		if (strncmp(line, "RssAnon:", 8) == 0)
			status->rss_anon = strtol(line + 8, NULL, 10);
		else if (strncmp(line, "RssFile:", 8) == 0)
			status->rss_file = strtol(line + 8, NULL, 10);
	}

	fclose(file);

	status->rss_sum = status->rss_anon + status->rss_file;
}

int is_cmd_available(const char *cmd)
{
	char cmd_path[PATH_MAX];
	snprintf(cmd_path, sizeof(cmd_path), "%s --version > /dev/null 2>&1", cmd);

	int status = system(cmd_path);

	if (status == -1)
		return 0;

	if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
		return 1;

	return 0;
}

void set_fd_limit(int new_limit)
{
	struct rlimit lim;

	if (getrlimit(RLIMIT_NOFILE, &lim) == -1) {
		CLI_ERROR("getrlimit failed.");
		exit(EXIT_FAILURE);
	}

	CLI_OUTPUT("Current limits: soft = %ld, hard = %ld", lim.rlim_cur, lim.rlim_max);

	lim.rlim_cur = new_limit;
	lim.rlim_max = new_limit;

	if (setrlimit(RLIMIT_NOFILE, &lim) == -1) {
		CLI_ERROR("setrlimit failed.");
		exit(EXIT_FAILURE);
	}

	if (getrlimit(RLIMIT_NOFILE, &lim) == -1) {
		CLI_ERROR("getrlimit failed.");
		exit(EXIT_FAILURE);
	}

	CLI_OUTPUT("New limits: soft = %ld, hard = %ld", lim.rlim_cur, lim.rlim_max);
}

int get_file_stat_info(const char *filename, struct file_info *info)
{
	struct stat file_stat;

	if (stat(filename, &file_stat) == -1)
		return -1;

	info->inode = file_stat.st_ino;
	info->mtime = file_stat.st_mtime;
	info->dev = file_stat.st_dev;

	return 0;
}

uint32_t __seed = 123456789;

unsigned long long find_symbol_address(const char *symbol_name)
{
	FILE *file = fopen("/proc/kallsyms", "r");
	if (!file) {
		perror("Failed to open /proc/kallsyms");
		return 0;
	}

	char line[PATH_MAX];
	unsigned long long address = 0;

	while (fgets(line, sizeof(line), file)) {
		char *space_ptr = strchr(line, ' ');
		if (space_ptr) {
			*space_ptr = '\0';
			char *symbol = space_ptr + 3;
			char *newline_ptr = strchr(symbol, '\n');
			if (newline_ptr) {
				*newline_ptr = '\0';
			}

			if (strcmp(symbol, symbol_name) == 0) {
				address = strtoull(line, NULL, 16);
				break;
			}
		}
	}

	fclose(file);
	return address ? address : (unsigned long long)NULL;
}

#define __MAX_STACK_SIZE 127

void traverse_cgroup_dirs(cgroup_callback_t callback)
{
	const char *cgroup_path = get_cgroup_mount_path();
	if (!cgroup_path) {
		fprintf(stderr, "Failed to get cgroup mount path.\n");
		return;
	}

	char full_path[PATH_MAX];
	char relative_path[PATH_MAX] = "";

	DIR **dir_stack = (DIR **)malloc(__MAX_STACK_SIZE * sizeof(DIR *));
	char **path_stack = (char **)malloc(__MAX_STACK_SIZE * sizeof(char *));
	for (int i = 0; i < __MAX_STACK_SIZE; i++) {
		path_stack[i] = (char *)malloc(PATH_MAX * sizeof(char));
	}

	int stack_index = 0;

	dir_stack[stack_index] = opendir(cgroup_path);
	if (!dir_stack[stack_index]) {
		CLI_ERROR("Failed to open cgroup directory %s", cgroup_path);
		goto cleanup;
	}
	strcpy(path_stack[stack_index], "");

	while (stack_index >= 0) {
		DIR *dir = dir_stack[stack_index];
		char *current_path = path_stack[stack_index];
		struct dirent *entry;

		while ((entry = readdir(dir)) != NULL) {
			if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
				continue;

			snprintf(relative_path, sizeof(relative_path), "%s/%s", current_path, entry->d_name);

			snprintf(full_path, sizeof(full_path), "%s/%s", cgroup_path, relative_path);
			struct stat st;
			if (stat(full_path, &st) == 0 && S_ISDIR(st.st_mode)) {
				callback(relative_path);
				if (stack_index < __MAX_STACK_SIZE - 1) {
					stack_index++;
					dir_stack[stack_index] = opendir(full_path);
					if (dir_stack[stack_index]) {
						strcpy(path_stack[stack_index], relative_path);
					} else {
						CLI_ERROR("Failed to open subdirectory");
						stack_index--;
					}
				} else {
					CLI_ERROR("Directory stack overflow");
				}
			}
		}

		closedir(dir_stack[stack_index]);
		stack_index--;
	}

cleanup:
	for (int i = 0; i < __MAX_STACK_SIZE; i++) {
		free(path_stack[i]);
	}
	free(path_stack);
	free(dir_stack);
}

#define ENV_BUFFER_SIZE 8192
static char env_buffer[ENV_BUFFER_SIZE + 1];

char *get_env_var_by_pid(pid_t pid, char **var_names, int var_name_count)
{
	char path[256];
	char *result = NULL;
	int found = 0;

	snprintf(path, sizeof(path), "/proc/%d/environ", pid);

	FILE *file = fopen(path, "r");
	if (!file)
		return NULL;

	char *previous_part = NULL;
	size_t previous_size = 0;
	memset(env_buffer, 0, ENV_BUFFER_SIZE + 1);

	while (!found) {
		size_t bytes_read = fread(env_buffer, 1, ENV_BUFFER_SIZE, file);
		if (bytes_read == 0)
			break;

		size_t start = 0;

		if (previous_part) {
			size_t total_size = previous_size + bytes_read;
			char *combined = (char *)malloc(total_size + 1);
			if (!combined) {
				fclose(file);
				return NULL;
			}

			memcpy(combined, previous_part, previous_size);
			memcpy(combined + previous_size, env_buffer, bytes_read);
			combined[total_size] = '\0';

			free(previous_part);
			previous_part = NULL;
			previous_size = 0;

			char *env = combined;
			while (env < combined + total_size) {
				size_t len = strlen(env);
				if (len == 0) {
					env++;
					continue;
				}

				for (size_t i = 0; i < var_name_count; i++) {
					int var_name_len = strlen(var_names[i]);
					if (!strncmp(env, var_names[i], var_name_len) && env[var_name_len] == '=') {
						result = strdup(env + var_name_len + 1);
						found = 1;
						break;
					}
				}

				if (found)
					break;

				env += len + 1;
			}

			free(combined);
			if (found)
				break;

			start = bytes_read - (env - combined);
		}

		for (size_t i = start; i < bytes_read;) {
			char *env = &env_buffer[i];
			size_t len = strlen(env);

			if (i + len >= bytes_read) {
				previous_size = bytes_read - i;
				previous_part = (char *)malloc(previous_size);
				if (!previous_part) {
					fclose(file);
					return NULL;
				}
				memcpy(previous_part, env, previous_size);
				break;
			}

			for (size_t i = 0; i < var_name_count; i++) {
				int var_name_len = strlen(var_names[i]);
				if (!strncmp(env, var_names[i], var_name_len) && env[var_name_len] == '=') {
					result = strdup(env + var_name_len + 1);
					found = 1;
					break;
				}
			}

			if (found)
				break;

			i += len + 1;
		}
	}

	fclose(file);
	if (previous_part)
		free(previous_part);

	return result;
}

uint64_t get_current_ms(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);

	return (uint64_t)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

uint64_t get_current_uptime_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

void rm_template_param(char *demangled)
{
	char *write_pos = demangled;
	int depth = 0;

	if (!write_pos)
		return;

	for (char *read_pos = demangled; *read_pos != '\0'; read_pos++) {
		if (*read_pos == '<')
			depth++;
		else if (*read_pos == '>')
			depth--;
		else if (depth == 0)
			*write_pos++ = *read_pos;
	}
	*write_pos = '\0';
}

#define BUFFER_SIZE 4096

int copy_file(const char *file_path, const char *target_file_path)
{
	int src_fd = -1, dest_fd = -1;
	ssize_t bytes_read, bytes_written;
	char buffer[BUFFER_SIZE];
	int ret = -1;

	src_fd = open(file_path, O_RDONLY);
	if (src_fd < 0) {
		CLI_ERROR("Failed to open source file");
		goto out;
	}

	dest_fd = open(target_file_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (dest_fd < 0) {
		CLI_ERROR("Failed to open/create destination file");
		goto out;
	}

	while ((bytes_read = read(src_fd, buffer, BUFFER_SIZE)) > 0) {
		bytes_written = write(dest_fd, buffer, bytes_read);
		if (bytes_written != bytes_read) {
			CLI_ERROR("Failed to write data to destination file");
			goto out;
		}
	}

	if (bytes_read < 0) {
		CLI_ERROR("Failed to read data from source file");
		goto out;
	}

	close(src_fd);
	src_fd = -1;
	close(dest_fd);
	dest_fd = -1;

	ret = 0;

out:
	if (src_fd >= 0) {
		close(src_fd);
	}
	if (dest_fd >= 0) {
		close(dest_fd);
	}
	return ret;
}

#define MAX_MAPS_PATH 4096
static char maps_path[MAX_MAPS_PATH] = { 0 };
static char maps_line[MAX_MAPS_PATH] = { 0 };

struct maps_info *get_maps_info(int pid, int *count, char permission_flag, char *debug_maps)
{
	FILE *fp;
	char filename[256];
	struct maps_info *info = NULL;
	int allocated = 64;
	int index = 0;
	uint64_t current_bias = 0;

	if (debug_maps) {
		if (snprintf(filename, sizeof(filename), "%s", debug_maps) >= sizeof(filename)) {
			CLI_OUTPUT("debug_maps path too long");
			goto out;
		}
	} else {
		snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
	}

	fp = fopen(filename, "r");
	if (!fp) {
		CLI_OUTPUT("Failed to open file %s", filename);
		goto out;
	}

	info = malloc(allocated * sizeof(struct maps_info));
	if (!info)
		goto out;

	while (fgets(maps_line, sizeof(maps_line), fp)) {
		uint64_t start, end, offset;
		char perm[5];
		int n;

		memset(maps_path, 0, MAX_MAPS_PATH);

		n = sscanf(maps_line, "%lx-%lx %4s %lx %*s %*s %4095s", &start, &end, perm, &offset, maps_path);
		if (n < 4)
			continue;

		if (!((perm[0] == 'r' ? PERMISSION_R : 0) & permission_flag) && !((perm[1] == 'w' ? PERMISSION_W : 0) & permission_flag) && !((perm[2] == 'x' ? PERMISSION_X : 0) & permission_flag))
			continue;

		if (index >= allocated) {
			allocated *= 2;
			info = realloc(info, allocated * sizeof(struct maps_info));
			if (!info) {
				CLI_OUTPUT("Failed to allocate memory realloc errno %d", errno);
				goto cleanup;
			}
		}

		/*
		 * Some golang binary may have one program header but cut it to multi segments.
		 * They has continuous address space & same permission & same path.
		 * We need to merge them to one to avoid bias calc failed & symbol broken.
		 */
		if (index >= 1) {
			if (info[index - 1].permission == (perm[0] | perm[1] | perm[2]) && strcmp(info[index - 1].path, maps_path) == 0) {
				info[index - 1].end = end;
				continue;
			}
		}

		info[index].start = start;
		info[index].end = end;
		info[index].permission = perm[0] | perm[1] | perm[2];
		info[index].path = strdup(maps_path);
		if (!info[index].path) {
			CLI_OUTPUT("Failed to allocate memory path\n");
			goto cleanup;
		}

		index++;
	}

	if (index == 0)
		goto cleanup;

	info = realloc(info, index * sizeof(struct maps_info));
	if (!info) {
		CLI_OUTPUT("Failed to allocate memory realloc, index: %d\n", index);
		goto cleanup;
	}
	*count = index;
	fclose(fp);
	return info;

cleanup:
	for (int i = 0; i < index; i++) {
		free(info[i].path);
	}
	free(info);
	info = NULL;
out:
	if (fp)
		fclose(fp);
	*count = 0;
	return NULL;
}

void free_maps_info(struct maps_info *maps, int count)
{
	for (int i = 0; i < count; i++)
		free(maps[i].path);

	free(maps);
}

#define BILLION 1000000000L
#define MILLION 1000000L

struct timespec __last_time = { 0, 0 };

void record_time_clear(void)
{
	__last_time.tv_sec = 0;
	__last_time.tv_nsec = 0;
	record_time();
}

void record_time(void)
{
	struct timespec current_time;
	clock_gettime(CLOCK_MONOTONIC, &current_time);

	if (__last_time.tv_sec != 0 || __last_time.tv_nsec != 0) {
		long seconds = current_time.tv_sec - __last_time.tv_sec;
		long nanoseconds = current_time.tv_nsec - __last_time.tv_nsec;
		if (nanoseconds < 0) {
			seconds -= 1;
			nanoseconds += BILLION;
		}

		long milliseconds = seconds * 1000 + nanoseconds / MILLION;
		long remaining_nanoseconds = nanoseconds % MILLION;

		printf("Time since last call: %ld.%06ld ms\n", milliseconds, remaining_nanoseconds);
	}
	__last_time = current_time;
}

static int hex_char_to_int(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	else if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	else
		return -1;
}

unsigned char *hex_string_to_binary(const char *hex_string, size_t *binary_length)
{
	size_t hex_length = strlen(hex_string);
	unsigned char *binary = NULL;

	if (hex_length % 2 != 0)
		return NULL;

	*binary_length = hex_length / 2;
	binary = (unsigned char *)malloc(*binary_length);
	if (!binary)
		goto out;

	for (size_t i = 0; i < *binary_length; ++i) {
		int high_nibble = hex_char_to_int(hex_string[2 * i]);
		int low_nibble = hex_char_to_int(hex_string[2 * i + 1]);
		if (high_nibble == -1 || low_nibble == -1)
			goto out;
		binary[i] = (high_nibble << 4) | low_nibble;
	}

	return binary;

out:
	if (binary) {
		free(binary);
		binary = NULL;
	}
	return NULL;
}

void clear_file_cache(FILE *fp)
{
	fflush(fp);
	int fd = fileno(fp);
	if (fd == -1)
		return;
	posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
}
