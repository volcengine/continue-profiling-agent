// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "cli_config.h"

struct cli_config *cli_config_init(const char *path)
{
	struct cli_config *config = malloc(sizeof(struct cli_config));
	if (!config) {
		CLI_ERROR("Failed to allocate memory for config");
		return NULL;
	}

	if (path)
		config->config_path = strdup(path);
	else
		config->config_path = NULL;
	config->items = NULL;
	config->items_len = 0;
	return config;
}

void add_config_item(struct cli_config *config, const char *name, const char *value)
{
	struct cli_config_item *item = malloc(sizeof(struct cli_config_item));
	if (!item)
		goto out;

	item->name = strdup(name);
	if (!item->name)
		goto free_item;

	item->value = strdup(value);
	if (!item->value)
		goto free_name;

	LL_APPEND(config->items, item);
	config->items_len++;
	return;

free_name:
	free((char *)item->name);
free_item:
	free(item);
out:
	CLI_ERROR("Failed to add config item");
}

static void free_config_item(struct cli_config_item *item)
{
	free((char *)item->name);
	free((char *)item->value);
	free(item);
}

void del_config_item(struct cli_config *config, const char *name)
{
	struct cli_config_item *item, *tmp;
	LL_FOREACH_SAFE(config->items, item, tmp)
	{
		if (strcmp(item->name, name) == 0) {
			LL_DELETE(config->items, item);
			config->items_len--;
			free_config_item(item);
			return;
		}
	}
}

void dump_config(struct cli_config *config)
{
	FILE *file = fopen(config->config_path, "w");
	if (!file) {
		CLI_ERROR("Failed to open file for writing");
		return;
	}

	struct cli_config_item *item;
	LL_FOREACH(config->items, item)
	fprintf(file, "%s: %s\n", item->name, item->value);

	fclose(file);
}

void load_config(struct cli_config *config, const char *path)
{
	FILE *file = fopen(path, "r");
	if (!file) {
		CLI_ERROR("Failed to open file %s for reading", path);
		return;
	}

	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	while ((read = getline(&line, &len, file)) != -1) {
		char *sep = strchr(line, ':');
		if (sep) {
			*sep = '\0';
			char *name = line;
			char *value = sep + 1;
			while (*value == ' ' || *value == '\t')
				value++;
			value[strcspn(value, "\n")] = '\0';
			add_config_item(config, name, value);
		}
	}

	free(line);
	fclose(file);
}

void cli_config_destroy(struct cli_config *config)
{
	struct cli_config_item *item, *tmp;
	LL_FOREACH_SAFE(config->items, item, tmp)
	{
		LL_DELETE(config->items, item);
		config->items_len--;
		free_config_item(item);
	}
	if (config->config_path)
		free((char *)config->config_path);
	free(config);
}

void print_all_config(struct cli_config *config)
{
	struct cli_config_item *item;
	LL_FOREACH(config->items, item)
	CLI_OUTPUT("%s: %s", item->name, item->value);
}

const char *get_config(struct cli_config *config, const char *name)
{
	struct cli_config_item *item;
	LL_FOREACH(config->items, item)
	if (strcmp(item->name, name) == 0)
		return item->value;

	return NULL;
}
