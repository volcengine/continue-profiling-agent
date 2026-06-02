// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CLI_CONFIG_H
#define CLI_CONFIG_H

#include "cli.h"
#include "utlist.h"

/**
 * @file cli_config.h
 * @brief Lightweight key/value config helpers for CPA store metadata.
 */

/**
 * struct cli_config_item - one config entry from a persisted config file
 * @name: config key
 * @value: config value
 * @next: intrusive next pointer used by the local linked list
 */
struct cli_config_item {
	const char *name;
	const char *value;
	struct cli_config_item *next;
};

/**
 * struct cli_config - in-memory config file representation
 * @config_path: source file path used for reload/dump operations
 * @items: linked list of key/value items
 * @items_len: cached item count
 */
struct cli_config {
	const char *config_path;
	struct cli_config_item *items;
	int items_len;
};

/**
 * cli_config_init - allocate a config object bound to a file path.
 * @path: source path used by persistence.
 * @return: initialized object or %NULL on allocation/parsing setup failure.
 */
struct cli_config *cli_config_init(const char *path);

/**
 * cli_config_destroy - free all allocations owned by config object.
 * @config: target object; no-op when %NULL.
 */
void cli_config_destroy(struct cli_config *config);

/**
 * add_config_item - add or replace one key/value pair.
 * @config: destination configuration object.
 * @name: key string.
 * @value: value string.
 */
void add_config_item(struct cli_config *config, const char *name, const char *value);

/**
 * del_config_item - remove one key/value pair.
 * @config: destination configuration object.
 * @name: key to remove.
 */
void del_config_item(struct cli_config *config, const char *name);

/**
 * get_config - lookup a value by key.
 * @config: source object.
 * @name: key to query.
 * @return: value string when found, %NULL otherwise.
 */
const char *get_config(struct cli_config *config, const char *name);

/**
 * dump_config - write current items back to its configured path.
 * @config: source object.
 */
void dump_config(struct cli_config *config);

/**
 * load_config - parse file contents into config object.
 * @config: destination object.
 * @path: file path to load.
 */
void load_config(struct cli_config *config, const char *path);

/**
 * print_all_config - print all entries for diagnostics.
 * @config: source object.
 */
void print_all_config(struct cli_config *config);

#endif /* CLI_CONFIG_H */
