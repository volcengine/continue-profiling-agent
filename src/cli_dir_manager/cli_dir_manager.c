// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "cli.h"
#include "cli_common.h"

#include "cli_dir_manager.h"

struct private_dir_info {
	char *name;
	char *basename;
	time_t creation_time;
	size_t size_mb;
};

int compare_creation_time(const void *a, const void *b)
{
	struct private_dir_info *dir_a = (struct private_dir_info *)a;
	struct private_dir_info *dir_b = (struct private_dir_info *)b;

	if (dir_a->creation_time < dir_b->creation_time)
		return -1;
	else if (dir_a->creation_time > dir_b->creation_time)
		return 1;
	else
		return 0;
}

time_t parse_creation_time(const char *folder_name, char *prefix)
{
	struct tm tm_info = { 0 };
	int year, month, day, hour = 0, minute = 0, second = 0;

	/*
	 * Store names are "<prefix>_yymmdd" or
	 * "<prefix>_yymmdd_start_HHMMSS". Unknown names sort as newest so
	 * retention cleanup does not aggressively delete unrelated folders.
	 */
	folder_name = folder_name + strlen(prefix) + 1;

	if (sscanf(folder_name, "%2d%2d%2d_start_%2d%2d%2d", &year, &month, &day, &hour, &minute, &second) == 6) {
	} else if (sscanf(folder_name, "%2d%2d%2d", &year, &month, &day) == 3) {
		hour = 0;
		minute = 0;
		second = 0;
	} else {
		return time(NULL);
	}

	tm_info.tm_year = year + 100;
	tm_info.tm_mon = month - 1;
	tm_info.tm_mday = day;
	tm_info.tm_hour = hour;
	tm_info.tm_min = minute;
	tm_info.tm_sec = second;
	tm_info.tm_isdst = -1;

	return mktime(&tm_info);
}

struct private_dir_info *create_dir_info_array(const char *store_dir, int *count, char *prefix)
{
	DIR *dir;
	struct dirent *entry;
	struct private_dir_info *directories = NULL;
	int dir_count = 0;

	if ((dir = opendir(store_dir)) == NULL) {
		CLI_ERROR("opendir %s failed", store_dir);
		*count = 0;
		return NULL;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_type == DT_DIR && strncmp(entry->d_name, prefix, strlen(prefix)) == 0)
			dir_count++;
	}

	directories = malloc(sizeof(struct private_dir_info) * dir_count);
	if (directories == NULL) {
		CLI_ERROR("malloc dir info failed");
		closedir(dir);
		*count = 0;
		return NULL;
	}

	rewinddir(dir);
	int idx = 0;
	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_type == DT_DIR && strncmp(entry->d_name, prefix, strlen(prefix)) == 0) {
			directories[idx].name = path_join(store_dir, entry->d_name);
			directories[idx].basename = strdup(entry->d_name);
			directories[idx].creation_time = parse_creation_time(entry->d_name, prefix);
			directories[idx].size_mb = get_directory_size(directories[idx].name) / 1024 / 1024;
			idx++;
		}
	}

	closedir(dir);
	*count = dir_count;
	return directories;
}

void free_dir_info_array(struct private_dir_info *dirs, int count)
{
	for (int i = 0; i < count; i++) {
		free(dirs[i].name);
		free(dirs[i].basename);
	}
	free(dirs);
}

char *add_time_to_day_store_dir_name(char *dir)
{
	if (dir == NULL)
		return NULL;

	time_t now;
	struct tm *tm_info;
	char time_str[16];

	time(&now);
	tm_info = localtime(&now);

	strftime(time_str, sizeof(time_str), "_start_%H%M%S", tm_info);

	size_t new_len = strlen(dir) + strlen(time_str) + 1;

	char *new_dir = (char *)malloc(new_len);
	if (new_dir == NULL)
		return NULL;

	strcpy(new_dir, dir);
	strcat(new_dir, time_str);

	free(dir);

	return new_dir;
}

void del_dir_with_prefix(char *dir_path)
{
	if (dir_path == NULL)
		return;

	/* Prefix deletion is string-based; callers must pass a precise prefix. */
	char *basename = strrchr(dir_path, '/');
	char parent_path[PATH_MAX];

	if (basename != NULL) {
		*basename = '\0';
		basename++;
		if (snprintf(parent_path, sizeof(parent_path), "%s", dir_path) >= sizeof(parent_path)) {
			CLI_ERROR("dir path too long: %s", dir_path);
			return;
		}
	} else {
		snprintf(parent_path, sizeof(parent_path), ".");
		basename = dir_path;
	}

	DIR *dir = opendir(parent_path);
	if (dir == NULL) {
		CLI_ERROR("opendir %s failed.", parent_path);
		return;
	}

	struct dirent *entry;
	struct stat statbuf;
	char full_path[PATH_MAX];

	while ((entry = readdir(dir)) != NULL) {
		snprintf(full_path, sizeof(full_path), "%s/%s", parent_path, entry->d_name);

		if (stat(full_path, &statbuf) == 0 && S_ISDIR(statbuf.st_mode))
			if (strncmp(entry->d_name, basename, strlen(basename)) == 0)
				remove_directory(full_path);
	}

	closedir(dir);
}

#define MAX_PERFIX_LEN 64

struct dir_info *get_single_store_dir_name(const char *store_dir, char *prefix, int max_usage, int persistent_day)
{
	int count = 0;
	struct dir_info *dir_info = NULL;
	struct private_dir_info *dirs = NULL;
	char *dir_name = NULL;
	int target_usage = max_usage - 100; // min reserve 100MB.

	int sum_usage = 0, i = 0;

	time_t raw_time;
	struct tm *time_info;
	char date_buffer[7];
	char del_date_buffer[7];

	if (strlen(prefix) > MAX_PERFIX_LEN) {
		CLI_ERROR("Perfix too long, %s.len > 64", prefix);
		return NULL;
	}

	if (persistent_day <= 0) {
		CLI_ERROR("persistent_day must be greater than 0");
		return NULL;
	}

	time(&raw_time);
	time_info = localtime(&raw_time);
	strftime(date_buffer, sizeof(date_buffer), "%y%m%d", time_info);

	/* Delete marker is shifted back by full days to keep the retention window. */
	raw_time -= (persistent_day + 1) * 86400;
	time_info = localtime(&raw_time);
	strftime(del_date_buffer, sizeof(del_date_buffer), "%y%m%d", time_info);

	char result_buffer[128];
	snprintf(result_buffer, sizeof(result_buffer), "%s_%s", prefix, date_buffer);

	char del_result_buffer[128];
	snprintf(del_result_buffer, sizeof(del_result_buffer), "%s_%s", prefix, del_date_buffer);

	char *del_dir = path_join(store_dir, del_result_buffer);
	CLI_OUTPUT("del log in %s*", del_dir);
	del_dir_with_prefix(del_dir);
	free(del_dir);

	dir_name = path_join(store_dir, result_buffer);
	if (!dir_name) {
		CLI_ERROR("Failed to build store directory path");
		goto fail;
	}

	dir_info = calloc(1, sizeof(struct dir_info));
	if (!dir_info) {
		CLI_ERROR("malloc dir info failed");
		goto fail;
	}

	// set same_day_dir_num to zero
	dir_info->same_day_dir_num = 0;
	dirs = create_dir_info_array(store_dir, &count, prefix);
	if (dirs == NULL || count == 0) {
		CLI_ERROR("dir is empty %s %d", store_dir, count);
		goto mkdir;
	}

	for (i = 0; i < count; i++)
		sum_usage += dirs[i].size_mb;

	qsort(dirs, count, sizeof(struct private_dir_info), compare_creation_time);

	i = 0;

	/* Reclaim oldest directories first until the store is under target_usage. */
	while (sum_usage > target_usage && i < count) {
		CLI_OUTPUT("del dir %s, size %d MB", dirs[i].name, dirs[i].size_mb);
		remove_directory(dirs[i].name);
		sum_usage -= dirs[i].size_mb;
		i++;
	}

	int found = false;
	for (i = 0; i < count; i++) {
		if (strncmp(dirs[i].basename, result_buffer, strlen(result_buffer)) == 0) {
			found = true;
			dir_info->same_day_dir_num++;
		}
	}

	/* Avoid same-day collisions by adding a start-time suffix. */
	if (found)
		dir_name = add_time_to_day_store_dir_name(dir_name);
	if (!dir_name) {
		CLI_ERROR("Failed to allocate rotated store directory name");
		goto fail;
	}

mkdir:

	if (mkdir(dir_name, 0777) != 0) {
		CLI_ERROR("Failed to create directory %s: %s", dir_name, strerror(errno));
		goto fail;
	}

	int left = max_usage - sum_usage;

	/* Split remaining quota across retained days. */
	if (left < max_usage / persistent_day)
		dir_info->store_dir_max_usage = left;
	else
		dir_info->store_dir_max_usage = max_usage / persistent_day;

	dir_info->store_dir = dir_name;
	dir_name = NULL;

	CLI_OUTPUT("set dir to %s, max usage = %d MB", dir_info->store_dir, dir_info->store_dir_max_usage);

	free_dir_info_array(dirs, count);

	return dir_info;

fail:
	if (dir_name)
		free(dir_name);
	if (dir_info && dir_info->store_dir)
		free(dir_info->store_dir);
	if (dir_info)
		free(dir_info);
	if (dirs)
		free_dir_info_array(dirs, count);
	return NULL;
}
