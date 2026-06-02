// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "uthash.h"
#include <stdint.h>
#include <stdbool.h>
#include "cpa_env.h"
#include "gunwinder/unwinder.h"
#include "cpa_runtime.h"

struct parse_env_value_hash {
	char *env;
	UT_hash_handle hh;
};

struct cpa_env_record_state {
	char **record_env_name;
	int record_env_name_count;

	int kernel_only;

	struct parse_env_value_hash *parse_env_values_hash_list;
	int parse_env_values_hash_list_count;
};

struct cpa_env_record_state env_stat = { 0 };

bool cpa_env_should_parse(const char *env_name)
{
	struct parse_env_value_hash *p = NULL;
	if (!env_stat.kernel_only)
		return 1;
	HASH_FIND_STR(env_stat.parse_env_values_hash_list, env_name, p);
	if (p)
		return 1;
	return 0;
}

int cpa_env_record_num(void)
{
	return env_stat.parse_env_values_hash_list_count;
}

char **cpa_get_record_env(int *size)
{
	*size = env_stat.record_env_name_count;
	return env_stat.record_env_name;
}

static void cpa_env_add(const char *env_name)
{
	struct parse_env_value_hash *h = calloc(1, sizeof(struct parse_env_value_hash));
	if (!h)
		return;
	h->env = strdup(env_name);
	HASH_ADD_STR(env_stat.parse_env_values_hash_list, env, h);
	env_stat.parse_env_values_hash_list_count++;
}

enum cpa_worker_init_result cpa_env_record_init(void *cli_ctx, void *worker_ctx)
{
	const char *record_env_name = get_arg_by_name(cli_ctx, "record_env_name");
	const char *parse_env_arg = get_arg_by_name(cli_ctx, "parse_env_values");

	env_stat.kernel_only = atoi(get_arg_by_name(cli_ctx, "kernel_stack"));
	env_stat.record_env_name = get_single_list_args(record_env_name, &env_stat.record_env_name_count);

	if (env_stat.record_env_name_count == 1 && cli_arg_is_null_default(env_stat.record_env_name[0])) {
		free_single_list_args(env_stat.record_env_name, env_stat.record_env_name_count);
		env_stat.record_env_name = NULL;
		env_stat.record_env_name_count = 0;
	}

	char **parse_env_values = NULL;
	int parse_env_values_count = 0;
	parse_env_values = get_single_list_args(parse_env_arg, &parse_env_values_count);
	if (parse_env_values_count > 0 && !cli_arg_is_null_default(parse_env_values[0])) {
		CLI_OUTPUT_NO_END("Those Env Name Will Parse UserStack: ");
		for (int i = 0; i < parse_env_values_count; i++) {
			CLI_OUTPUT_NO_END("%s ", parse_env_values[i]);
			cpa_env_add(parse_env_values[i]);
		}
		CLI_OUTPUT("");
	}
	free_single_list_args(parse_env_values, parse_env_values_count);

	return CPA_INIT_SUCCESS;
}

void cpa_env_record_destroy(void *worker_ctx)
{
	struct parse_env_value_hash *p, *tmp;
	if (env_stat.parse_env_values_hash_list) {
		HASH_ITER (hh, env_stat.parse_env_values_hash_list, p, tmp) {
			HASH_DEL(env_stat.parse_env_values_hash_list, p);
			free(p->env);
			free(p);
		}
		env_stat.parse_env_values_hash_list_count = 0;
	}
	if (env_stat.record_env_name) {
		free_single_list_args(env_stat.record_env_name, env_stat.record_env_name_count);
		env_stat.record_env_name = NULL;
		env_stat.record_env_name_count = 0;
	}
}

struct cpa_worker env_worker = {
	.worker_name = "env_worker",
	.worker_ctx = NULL,
	.worker_index = 5,

	.init_fn = cpa_env_record_init,
	.destroy_fn = cpa_env_record_destroy,
	.pause_fn = NULL,
	.restore_fn = NULL,
	.timer_fn = NULL,
	.main_worker_fn = NULL,
};
