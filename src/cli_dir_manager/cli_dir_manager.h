// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CLI_DIR_MANAGER_H
#define CLI_DIR_MANAGER_H

/**
 * @file cli_dir_manager.h
 * @brief Helpers for selecting and creating CPA storage directories.
 */

/**
 * struct dir_info - resolved store directory metadata
 * @store_dir: selected output directory path
 * @store_dir_max_usage: size cap in megabytes
 * @same_day_dir_num: sequence number for same-day directory rotation
 */
struct dir_info {
	char *store_dir;
	int store_dir_max_usage;
	int same_day_dir_num;
};

/**
 * get_single_store_dir_name - resolve active store directory and rotation context.
 * @store_dir: base directory configured by user.
 * @prefix: optional filename prefix.
 * @max_usage: per-directory usage cap.
 * @persistent_day: day index used for stable naming.
 * @return: resolved directory info or %NULL.
 */
struct dir_info *get_single_store_dir_name(const char *store_dir, char *prefix, int max_usage, int persistent_day);

#endif /* CLI_DIR_MANAGER_H */
