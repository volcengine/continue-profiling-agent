// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "cli.h"
#include "cli_cmd_helper.h"
#include "cli_common.h"
#include "cli_profile_metadata.h"
#include "cli_stackmap.h"

#include <libiberty/demangle.h>
#include <sys/stat.h>

#if CPA_ENABLE_CPA_SHOW
#include "cpa_show_ffi.h"
#endif

enum {
	META_SHOW_FLAG_NONE = 0,
	META_SHOW_FLAG_RAW = 1 << 0,
	META_SHOW_FLAG_NO_PID = 1 << 1,
	META_SHOW_FLAG_NO_ENV = 1 << 2,
};

#define CPA_SHOW_CMDLINE "read starttime=00:00:00 endtime=00:00:00 output_num=1 output_prof=null show_range=0 use_cui=0 use_cache=0 split_path=null show_thread_name=0 no_pid=0 no_env=0 show_raw=0 "

static const char *target_cpu;
static const char *target_comm;
static const char *target_env;
static unsigned long target_cgroup_id;
static unsigned long target_pid;
static struct cpu_set cpu_set = { 0, NULL };
static struct metadata cpa_meta_data;
static struct cli_stackmap *flamegraph_map = NULL;
static FILE *flamegraph_output_fp = NULL;

struct sub_cmd sub_cmd_cpa_show = {
	.name = "show",
	.arg_list = CPA_SHOW_CMDLINE "target_pid=0 target_comm=null target_env=null target_cgroup_id=0 target_cpu=all",
	.help_str = "[CPA] inspect stored profile data as flamegraph output or in the embedded TUI.",
	.func = SUB_CMD_FUNC(cpa_show),
};

static int cpa_flamegraph_init(FILE *fp)
{
	if (flamegraph_map)
		cli_stackmap_destroy(flamegraph_map);
	flamegraph_map = cli_stackmap_init();
	flamegraph_output_fp = fp;

	return flamegraph_map ? 0 : -1;
}

static void cpa_flamegraph_input_metadata(struct metadata *data, int flags)
{
	char comm_pid[TASK_COMM_LEN * 2];

	if (flags & META_SHOW_FLAG_RAW) {
		cli_stackmap_append(flamegraph_map, data->raw);
		return;
	}

	if (!(flags & META_SHOW_FLAG_NO_ENV))
		cli_stackmap_append(flamegraph_map, data->env);
	if (flags & META_SHOW_FLAG_NO_PID)
		snprintf(comm_pid, TASK_COMM_LEN * 2, "%s", data->group_comm);
	else
		snprintf(comm_pid, TASK_COMM_LEN * 2, "%s:%d", data->group_comm, data->pid);

	cli_stackmap_append(flamegraph_map, comm_pid);
}

static void cpa_flamegraph_input_stack(const char *stack)
{
	cli_stackmap_append(flamegraph_map, stack);
}

static void cpa_flamegraph_input_stack_count(unsigned long count)
{
	cli_stackmap_done(flamegraph_map, count);
}

static int cpa_flamegraph_final(void)
{
	struct id_count *id_count;
	const char *stack_str;
	int stack_type = 0;

	FOR_EACH_STACKMAP_SORT_BY_COUNT(flamegraph_map, id_count)
	{
		FOR_EACH_STACKMAP_STR(flamegraph_map, id_count->ids_id, stack_str)
		{
			fprintf(flamegraph_output_fp, "%s;", stack_str);
		}
		stack_type++;
		fprintf(flamegraph_output_fp, " %ld\n", id_count->count);
	}

	cli_stackmap_destroy(flamegraph_map);
	flamegraph_map = NULL;

	return stack_type;
}

static int cpa_show_cui_run(const char *read_dir, const char *starttime)
{
#if CPA_ENABLE_CPA_SHOW
	const char *argv[6];

	argv[0] = "cpa show";
	argv[1] = "--read";
	argv[2] = read_dir;
	argv[3] = "--starttime";
	argv[4] = starttime;
	argv[5] = "--use_cui";
	return cpa_show_main(6, argv);
#else
	fprintf(stderr, "Error: -G/--use_cui requires Rust toolchain (cargo).\n"
			"Hint: build with the Rust bridge enabled.\n");
	return -1;
#endif
}

static int is_intersect(uint64_t starttime_set, uint64_t endtime_set, uint64_t starttime_record, uint64_t endtime_record, uint64_t *starttime, uint64_t *endtime)
{
	if (starttime_set <= endtime_record && endtime_set >= starttime_record) {
		*starttime = (starttime_set > starttime_record) ? starttime_set : starttime_record;
		*endtime = (endtime_set < endtime_record) ? endtime_set : endtime_record;
		return 1;
	}

	return 0;
}

static bool cpa_show_filter_func(struct metadata *data)
{
	if (target_cgroup_id != 0 && data->cg_id != target_cgroup_id)
		return true;
	if (cpu_set.bitmap != NULL && !is_cpu_in_set(&cpu_set, data->cpu))
		return true;
	if (target_comm != NULL && strncmp(data->group_comm, target_comm, strlen(target_comm)) != 0)
		return true;
	if (target_pid != 0 && data->pid != target_pid)
		return true;
	if (target_env != NULL && strncmp(data->env, target_env, CPA_ENV_LEN) != 0)
		return true;

	return false;
}

static int cpa_show_render(void *ctx)
{
	const char *read_file = get_arg_by_name(ctx, "read");
	const char *start_time_str = get_arg_by_name(ctx, "starttime");
	const char *end_time_str = get_arg_by_name(ctx, "endtime");
	const char *output_prof = get_arg_by_name(ctx, "output_prof");
	const char *split_path = get_arg_by_name(ctx, "split_path");
	bool show_range = atoi(get_arg_by_name(ctx, "show_range"));
	int output_num = atoi(get_arg_by_name(ctx, "output_num"));
	int use_cache = atoi(get_arg_by_name(ctx, "use_cache"));
	int show_thread_name = atoi(get_arg_by_name(ctx, "show_thread_name"));
	int general_show_flags = META_SHOW_FLAG_NONE;
	int out_ret = 0;
	int ret;
	uint64_t starttime = 0;
	uint64_t endtime = 0;
	uint64_t starttime_set;
	uint64_t endtime_set;
	int record_count = 0;
	long last_endtime = 0;
	int record_index = -1;
	char output_prof_path[PATH_MAX] = { 0 };
	struct stackmap_dump_info dump_info = { 0 };
	struct cli_stackmap_record_map *map = NULL;
	struct stackmap_record *record = NULL;
	struct id_count *id_count_all = NULL;
	struct id_count *id_count = NULL;
	FILE *fp = NULL;

	if (cli_arg_is_null_default(output_prof))
		output_prof = NULL;

	if (atoi(get_arg_by_name(ctx, "no_pid")))
		general_show_flags |= META_SHOW_FLAG_NO_PID;
	if (atoi(get_arg_by_name(ctx, "no_env")))
		general_show_flags |= META_SHOW_FLAG_NO_ENV;
	if (atoi(get_arg_by_name(ctx, "show_raw")))
		general_show_flags |= META_SHOW_FLAG_RAW;

	starttime_set = convert_time_to_seconds(start_time_str);
	if (starttime_set == UINT64_MAX) {
		CLI_ERROR("Invalid starttime: %s", start_time_str);
		return -1;
	}
	endtime_set = convert_time_to_seconds(end_time_str);
	if (endtime_set == UINT64_MAX) {
		CLI_ERROR("Invalid endtime: %s", end_time_str);
		return -1;
	}
	starttime_set *= 1000;
	endtime_set *= 1000;

	if (output_num <= 0) {
		CLI_ERROR("output_num should be greater than 0");
		return -1;
	}

	ret = cli_stackmap_fetch_dump_info(read_file, &dump_info, use_cache);
	if (ret) {
		CLI_ERROR("cli_stackmap_fetch_dump_info failed");
		return -1;
	}

	CLI_OUTPUT_NO_END("Record Time From [ %s ] to ", convert_millisecond_to_time(dump_info.start));
	CLI_OUTPUT("[ %s ] Records Num: %d", convert_millisecond_to_time(dump_info.end), dump_info.record_count);

	if (show_range)
		goto end;

	map = cli_stackmap_reload(read_file, use_cache);
	if (!map) {
		CLI_ERROR("Failed to reload stackmap metadata");
		out_ret = -1;
		goto end;
	}

	CLI_OUTPUT("Choose formatter [ flamegraph ]");

	if (starttime_set > endtime_set && endtime_set != 0) {
		CLI_OUTPUT_NO_END("Time range not corrent [ %s -", convert_millisecond_to_time(starttime_set));
		CLI_OUTPUT(" %s ]", convert_millisecond_to_time(endtime_set));
		out_ret = -1;
		goto end;
	}

	if (endtime_set != 0) {
		int intersect = is_intersect(starttime_set, endtime_set, dump_info.start, dump_info.end, &starttime, &endtime);

		if (!intersect) {
			CLI_OUTPUT_NO_END("Not Found Record in Range [ %s -", convert_millisecond_to_time(starttime_set));
			CLI_OUTPUT(" %s ]", convert_millisecond_to_time(endtime_set));
			goto end;
		}
	} else {
		starttime = starttime_set;
	}

	for (int i = 0; i < dump_info.record_count; i++) {
		last_endtime = dump_info.records[i].endtime;

		if (endtime != 0 && dump_info.records[i].starttime > endtime)
			break;

		if (record_index == -1 && dump_info.records[i].starttime <= starttime && dump_info.records[i].endtime >= starttime) {
			record_index = i;
		}

		if (record_index != -1) {
			record_count++;
			if (endtime != 0 && dump_info.records[i].starttime <= endtime && dump_info.records[i].endtime >= endtime) {
				break;
			}
		}
	}

	if (record_index == -1) {
		CLI_ERROR("Not Found Record in Start in %s, Export First Record.", convert_millisecond_to_time(starttime));
		record_index = 0;
	}

	if (endtime != 0)
		output_num = record_count;

	if (output_num <= 0) {
		CLI_ERROR("No records selected in requested range");
		out_ret = -1;
		goto end;
	}

	if (record_index + output_num > dump_info.record_count) {
		CLI_ERROR("Not Found Enough Records Start in %s Len %d, max is %d", start_time_str, output_num, dump_info.record_count - record_index);
		out_ret = -1;
		goto end;
	}

	starttime = dump_info.records[record_index].starttime;
	endtime = dump_info.records[record_index + output_num - 1].endtime;
	record = &dump_info.records[record_index];
	record->id_count = NULL;

	if (atoi(get_arg_by_name(ctx, "use_cui"))) {
		const char *starttime_arg = get_arg_by_name(ctx, "starttime");

		CLI_OUTPUT("Use CUI Mode (cpa_show) start=%s", starttime_arg);
		ret = cpa_show_cui_run(read_file, starttime_arg);
		if (ret != 0) {
			CLI_ERROR("cpa_show_main failed: %d", ret);
			out_ret = -1;
		}
		goto end;
	}

	if (!cli_arg_is_null_default(split_path)) {
		struct stat path_stat;

		CLI_OUTPUT("Split Path: %s", split_path);
		if (stat(split_path, &path_stat) != 0) {
			CLI_ERROR("split dir path not exists %s, continue with no split", split_path);
		} else {
			char *source_conf;
			char *target_conf;

			cli_stackmap_split(record, output_num, read_file, split_path, use_cache);

			source_conf = path_join(read_file, "conf");
			target_conf = path_join(split_path, "conf");
			copy_file(source_conf, target_conf);
			CLI_OUTPUT("Split done to %s", split_path);

			free(source_conf);
			free(target_conf);
			goto end;
		}
	}

	id_count_all = cli_stackmap_dump(read_file, record, output_num);

	CLI_OUTPUT_NO_END("Export Record Time From [ %s -", convert_millisecond_to_time(starttime));
	CLI_OUTPUT(" %s ]", convert_millisecond_to_time(endtime));

	if (!output_prof) {
		snprintf(output_prof_path, PATH_MAX, "cpa_%s_%d.prof", convert_millisecond_to_time(starttime), output_num);
		output_prof = output_prof_path;
	}

	fp = fopen(output_prof, "w");
	if (!fp) {
		CLI_ERROR("Open %s Failed", output_prof);
		goto end;
	}

	if (cpa_flamegraph_init(fp)) {
		CLI_ERROR("flamegraph init failed");
		goto close_fp;
	}

	FOR_EACH_ID_COUNT_SORT_BY_COUNT(id_count_all, id_count)
	{
		struct ids_hash *ids = NULL;
		struct str_hash *str = NULL;

		HASH_FIND_INT(map->ids, &id_count->ids_id, ids);
		if (!ids) {
			CLI_ERROR("Not Found ids in %s", convert_millisecond_to_time(starttime));
			continue;
		}

		HASH_FIND_INT(map->str, &ids->ids[0], str);
		if (!str || str->str[0] == '#')
			continue;

		ret = parse_metadata(str->str, &cpa_meta_data);
		if (ret) {
			cpa_flamegraph_input_stack(str->str);
		} else {
			if (cpa_show_filter_func(&cpa_meta_data))
				continue;

			cpa_flamegraph_input_metadata(&cpa_meta_data, general_show_flags);
			if (show_thread_name)
				cpa_flamegraph_input_stack(cpa_meta_data.comm);
		}

		for (int i = 1; i < ids->ids_len; i++) {
			char *final_str = NULL;
			char *demangle_str = NULL;

			HASH_FIND_INT(map->str, &ids->ids[i], str);
			if (!str) {
				final_str = "<# STRMAP LOST ID #>";
			} else if (strncmp(str->str, "_Z", 2) == 0) {
				demangle_str = cplus_demangle(str->str, DMGL_AUTO);
				if (demangle_str) {
					rm_template_param(demangle_str);
					final_str = demangle_str;
				} else {
					final_str = str->str;
				}
			} else {
				final_str = str->str;
			}

			cpa_flamegraph_input_stack(final_str);
			free(demangle_str);
		}

		cpa_flamegraph_input_stack_count(id_count->count);
	}

	int stack_type = cpa_flamegraph_final();
	cli_stackmap_dump_free(id_count_all);
	id_count_all = NULL;

	CLI_OUTPUT_NO_END("Write  [ %s -", convert_millisecond_to_time(starttime));
	CLI_OUTPUT(" %s ] Record to %s, Stack Type %d", convert_millisecond_to_time(endtime), output_prof, stack_type);

close_fp:
	fclose(fp);

end:
	if (record && record->id_count) {
		struct id_count *record_id_count;
		struct id_count *tmp;

		HASH_ITER (hh, record->id_count, record_id_count, tmp) {
			HASH_DEL(record->id_count, record_id_count);
			free(record_id_count);
		}
	}

	if (map)
		cli_stackmap_record_map_free(map);
	if (dump_info.records)
		free(dump_info.records);
	if (flamegraph_map)
		cli_stackmap_destroy(flamegraph_map);

	(void)last_endtime;
	return out_ret;
}

int SUB_CMD_FUNC(cpa_show)(void *ctx)
{
	int ret;

	target_cpu = get_arg_by_name(ctx, "target_cpu");
	target_cgroup_id = atol(get_arg_by_name(ctx, "target_cgroup_id"));
	target_comm = get_arg_by_name(ctx, "target_comm");
	target_env = get_arg_by_name(ctx, "target_env");
	target_pid = atoi(get_arg_by_name(ctx, "target_pid"));

	if (cli_arg_is_null_default(target_env))
		target_env = NULL;

	if (cli_arg_is_null_default(target_comm))
		target_comm = NULL;

	if (strncmp(target_cpu, "all", strlen("all")) != 0)
		cpu_set = parse_cpu_set(target_cpu);

	ret = cpa_show_render(ctx);

	if (cpu_set.bitmap)
		free_cpu_set(&cpu_set);

	return ret;
}
