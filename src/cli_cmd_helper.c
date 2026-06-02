// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "cli_cmd_helper.h"
#include "cli_output.h"
#include "cli_config.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/ioctl.h>

struct arg_parse_item {
	const char *full_name;
	int single_name;
	const char *help_str;
	char *val;
	bool arg_required;

	char *_default_val;
	bool _required;
	bool _accessed;
};

#define ARG_DEFINE(full_name, single_name, help_str, arg_required)                                                                                                                                                                                             \
	{                                                                                                                                                                                                                                                      \
		full_name, single_name, help_str, NULL, arg_required, NULL, false, false                                                                                                                                                                       \
	}

#define NO_SINGLE_NAME 0

struct arg_parse_item arg_parse_item_list[] = {
	ARG_DEFINE("config", 'C', "Use %config file override commandline option. Format: {arg_name}: {arg_val}", true),
	ARG_DEFINE("duration", 'd', "stop monitor after N seconds; 0 means no duration limit.", true),
	ARG_DEFINE("verbose", 'v', "verbose output.", false),
	ARG_DEFINE("help", 'h', "show help message.", false),
	ARG_DEFINE("btf_path", 'b', "absolute path to a custom BTF file used by the BPF backend.", true),
	ARG_DEFINE("comm", 'n', "comm filter for cpa monitor. Requires the BPF backend.", true),
	ARG_DEFINE("pid", 'p', "pid filter for cpa monitor. Requires the BPF backend.", true),

	ARG_DEFINE("store_dir", 's', "directory where continuous CPA stores are written.", true),
	ARG_DEFINE("freq", 'F', "sampling frequency in Hz.", true),
	ARG_DEFINE("record_interval", 'r', "store rotation and query granularity in seconds.", true),
	ARG_DEFINE("persistent_day", 'P', "retain only the latest N days of continuous store directories.", true),
	ARG_DEFINE("kernel_stack", 'K', "capture kernel-space stacks only. Requires the BPF backend.", false),
	ARG_DEFINE("record_env_name", 'R', "record these env keys into metadata so show can filter on them. Use ',' to pass multiple names.", true),
	ARG_DEFINE("parse_env_values", 'V', "only unwind user stacks for processes whose recorded env values match this comma-separated list.", true),
	ARG_DEFINE("max_cache_size_mb", NO_SINGLE_NAME, "restart monitor when symbol/debug cache usage exceeds this limit in MB.", true),
	ARG_DEFINE("max_store_size_mb", NO_SINGLE_NAME, "restart monitor and trim old store directories when store usage exceeds this limit in MB.", true),
	ARG_DEFINE("debug_option", NO_SINGLE_NAME, "debug capture option in the form {pid},{sample_freq},{dump_path}.", true),
	ARG_DEFINE("log_print_cycles", NO_SINGLE_NAME, "print local runtime statistics every N timer cycles.", true),
	ARG_DEFINE("bench", NO_SINGLE_NAME, "print DWARF unwind benchmark statistics in runtime stats.", false),
	ARG_DEFINE("stack_size", NO_SINGLE_NAME, "user stack capture buffer size in bytes for the BPF backend; must be 4K-aligned and within [4096, 65536].", true),
	ARG_DEFINE("disable_sym", 'S', "disable symbol parsing and keep raw addresses where applicable.", false),
	ARG_DEFINE("include_full_path", NO_SINGLE_NAME, "keep full file paths in rendered stack frames where available.", false),
	ARG_DEFINE("strip_name_disable", NO_SINGLE_NAME, "disable Go symbol name stripping.", false),
	ARG_DEFINE("backend", NO_SINGLE_NAME, "sampling backend to use: bpf or perf. perf only supports on-cpu continuous profiling.", true),
	ARG_DEFINE("oneshot", NO_SINGLE_NAME, "write a single one-shot profile instead of rotating store directories. Requires the BPF backend.", false),

	/* show */
	ARG_DEFINE("read", 'r', "input CPA profile directory.", true),
	ARG_DEFINE("use_cui", 'G', "open the embedded cpa_show terminal UI.", false),
	ARG_DEFINE("show_range", 'p', "print available record time range and exit.", false),
	ARG_DEFINE("starttime", 'B', "start offset time in HH:MM:SS from the first captured record.", true),
	ARG_DEFINE("endtime", 'E', "end offset time in HH:MM:SS from the first captured record.", true),
	ARG_DEFINE("output_prof", 'o', "output flamegraph file path.", true),
	ARG_DEFINE("output_num", 'n', "number of records to export from the selected time point; must be a positive integer.", true),
	ARG_DEFINE("use_cache", 'u', "reuse decompressed files under decompressed/ when they already exist.", false),
	ARG_DEFINE("show_thread_name", 'S', "include thread names in flamegraph output.", false),
	ARG_DEFINE("no_pid", 'P', "omit pid suffixes from flamegraph metadata labels.", false),
	ARG_DEFINE("no_env", 'V', "omit env labels from flamegraph metadata labels.", false),
	ARG_DEFINE("show_raw", 'R', "render raw metadata entries instead of formatted CPA labels.", false),
	ARG_DEFINE("target_cpu", NO_SINGLE_NAME, "filter to CPUs in a standard CPU set such as \"1-3,5,7-9\".", true),
	ARG_DEFINE("target_cgroup_id", NO_SINGLE_NAME, "filter to one cgroup ID.", true),
	ARG_DEFINE("target_comm", NO_SINGLE_NAME, "filter to one process group comm.", true),
	ARG_DEFINE("target_pid", NO_SINGLE_NAME, "filter to one pid.", true),
	ARG_DEFINE("target_env", NO_SINGLE_NAME, "filter to one recorded env value.", true),
	ARG_DEFINE("split_path", NO_SINGLE_NAME, "export the selected time range as raw split files into this directory.", true),

	/* profile */
	ARG_DEFINE("offcpu", 'u', "collect off-CPU samples. Requires the BPF backend.", false),
	ARG_DEFINE("max_queue_size", 'm', "maximum in-memory stack event queue length before backpressure.", true),
	ARG_DEFINE("probe", NO_SINGLE_NAME, "capture stacks only when this probe fires, using bpftrace-style syntax such as 'kprobe:try_to_free_pages' or 'tracepoint:vmscan:mm_shrink_slab_start'. Requires the BPF backend.", true),

};

struct arg_ctx {
	struct arg_parse_item item_list[(sizeof(arg_parse_item_list) / sizeof(struct arg_parse_item))];
	int size;
	char *arg;
};

const char *g_args = NULL;
const char *g_prog_name = NULL;
const char *g_prog_desc = NULL;
struct sub_cmd **g_sub_cmd_list = NULL;
int g_sub_cmd_list_len = 0;

static struct sub_cmd *find_sub_cmd(const char *name);
static int do_sub_cmd(struct sub_cmd *cmd, int argc, const char *argv[]);
static int get_parse_args(struct arg_ctx *ctx, const char *arg_list);

static int get_longest_sub_cmd_len(void)
{
	int i, max = 0;
	for (i = 0; i < (sizeof(arg_parse_item_list) / sizeof(struct arg_parse_item)); i++)
		if (strlen(arg_parse_item_list[i].full_name) > max)
			max = strlen(arg_parse_item_list[i].full_name);
	/* add length of short option */
	return max + strlen(",-s");
}

#define START_SPACE "       "
#define TMP_BUFFER_SIZE 1024

static int get_term_width(void)
{
	const char *cols = getenv("COLUMNS");
	if (cols && cols[0] != '\0') {
		int v = atoi(cols);
		if (v > 0)
			return v;
	}

	struct winsize ws;
	memset(&ws, 0, sizeof(ws));
	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
		return ws.ws_col;

	return 120;
}

static void print_spaces(int n)
{
	for (int i = 0; i < n; i++)
		putchar(' ');
}

static int print_wrapped_segment_len(const char *s, size_t len, int col, int indent_col, int width)
{
	const char *p = s;
	const char *end = s + len;
	bool need_space = false;

	while (p < end) {
		while (p < end && (*p == ' ' || *p == '\t')) {
			need_space = true;
			p++;
		}
		if (p >= end)
			break;

		const char *w = p;
		size_t wlen = 0;
		while (p + wlen < end && p[wlen] != ' ' && p[wlen] != '\t')
			wlen++;

		if (need_space) {
			if (col + 1 + (int)wlen > width && col > indent_col) {
				putchar('\n');
				print_spaces(indent_col);
				col = indent_col;
			} else {
				putchar(' ');
				col++;
			}
			need_space = false;
		} else if (col + (int)wlen > width && col > indent_col) {
			putchar('\n');
			print_spaces(indent_col);
			col = indent_col;
		}

		fwrite(w, 1, wlen, stdout);
		col += (int)wlen;
		p += wlen;
	}

	return col;
}

static const char *find_first_sentence_break(const char *s, size_t len)
{
	for (size_t i = 0; i + 1 < len; i++) {
		if (s[i] == '.' && s[i + 1] == ' ')
			return s + i;
	}
	return NULL;
}

static int print_wrapped_segment_len_prefer_sentence(const char *s, size_t len, int col, int indent_col, int width)
{
	const char *p = find_first_sentence_break(s, len);
	if (!p)
		return print_wrapped_segment_len(s, len, col, indent_col, width);

	size_t first_len = (size_t)(p - s) + 1;
	size_t rest_off = (size_t)(p - s) + 2;
	if (rest_off > len)
		return print_wrapped_segment_len(s, len, col, indent_col, width);

	size_t rest_len = len - rest_off;
	int avail = width - indent_col;

	if (avail > 0 && (int)first_len <= avail && (int)len > avail && (int)first_len + 1 + (int)rest_len > avail) {
		col = print_wrapped_segment_len(s, first_len, col, indent_col, width);
		putchar('\n');
		print_spaces(indent_col);
		col = indent_col;
		col = print_wrapped_segment_len(s + rest_off, rest_len, col, indent_col, width);
		return col;
	}

	return print_wrapped_segment_len(s, len, col, indent_col, width);
}

static void print_wrapped_help(const char *help_str, const char *suffix, int indent_col, int width)
{
	int col = indent_col;
	bool has_nl = strchr(help_str, '\n') != NULL;
	bool suffix_printed = false;
	const char *p = help_str;

	for (;;) {
		const char *nl = strchr(p, '\n');
		size_t seg_len = nl ? (size_t)(nl - p) : strlen(p);
		col = print_wrapped_segment_len_prefer_sentence(p, seg_len, col, indent_col, width);

		if (!suffix_printed && has_nl) {
			col = print_wrapped_segment_len(suffix, strlen(suffix), col, indent_col, width);
			suffix_printed = true;
		}

		if (!nl)
			break;

		putchar('\n');
		print_spaces(indent_col);
		col = indent_col;
		p = nl + 1;
	}

	if (!suffix_printed)
		print_wrapped_segment_len(suffix, strlen(suffix), col, indent_col, width);
}

static void __print_arg_list(struct arg_ctx *ctx, const char *indent, int max_len, int size)
{
	int i, j;
	char sn;
	char tmp[TMP_BUFFER_SIZE];
	size_t cursor;
	int help_str_space = 0;
	int term_width = get_term_width();

	for (i = 0; i < size; i++) {
		char suffix[256];
		memset(tmp, 0, sizeof(tmp));
		/* Write the option prefix into a bounded buffer so help rendering cannot overflow. */
		cursor = snprintf(tmp, sizeof(tmp), "%s  --%s", indent, ctx->item_list[i].full_name);
		if (cursor >= sizeof(tmp))
			cursor = sizeof(tmp) - 1;

		sn = ctx->item_list[i].single_name;

		/* for only long option */
		if ((('a' <= sn && sn <= 'z') || ('A' <= sn && sn <= 'Z')) && cursor < sizeof(tmp) - 1) {
			int written = snprintf(tmp + cursor, sizeof(tmp) - cursor, ",-%c", ctx->item_list[i].single_name);

			if (written > 0) {
				cursor += written;
				if (cursor >= sizeof(tmp))
					cursor = sizeof(tmp) - 1;
			}
		}

		for (j = (int)cursor; j < max_len + 7 + (int)strlen(indent) && cursor < sizeof(tmp) - 1; j++) {
			tmp[cursor++] = ' ';
		}
		tmp[cursor] = '\0';

		/* get offset of help_str */
		help_str_space = cursor;
		/* write things before help_str */
		printf("%s", tmp);

		if (!ctx->item_list[i]._required)
			snprintf(suffix, sizeof(suffix), " default: %s", ctx->item_list[i]._default_val);
		else
			snprintf(suffix, sizeof(suffix), " [required]");

		print_wrapped_help(ctx->item_list[i].help_str, suffix, help_str_space, term_width);
		printf("\n");
	}
}

static void show_sub_cmd_help(struct sub_cmd *cmd)
{
	int max_len = get_longest_sub_cmd_len();
	int global_arg_len = 0;
	struct arg_ctx ctx;

	printf("Usage: %s %s [OPTIONS]\n", g_prog_name, cmd->name);
	if (cmd->help_str != NULL)
		printf("%s\n", cmd->help_str);

	printf("\n");
	printf(START_SPACE "Version: %s\n", CLI_VERSION);
	printf("\n");
	printf(START_SPACE "Generic Params:\n\n");

	memset(&ctx, 0, sizeof(struct arg_ctx));
	get_parse_args(&ctx, NULL);
	global_arg_len = ctx.size;
	__print_arg_list(&ctx, START_SPACE, max_len, global_arg_len);
	free(ctx.arg);

	if (cmd->arg_list != NULL) {
		printf("\n");
		printf(START_SPACE "Command Params:\n\n");
		memset(&ctx, 0, sizeof(struct arg_ctx));
		get_parse_args(&ctx, cmd->arg_list);
		__print_arg_list(&ctx, START_SPACE, max_len, ctx.size - global_arg_len);
		free(ctx.arg);
		printf("\n");
	}
}

void show_help(void)
{
	int i, j = 0;
	int max_len = get_longest_sub_cmd_len();
	int global_arg_len = 0;
	struct arg_ctx ctx;

	printf("Usage: %s {COMMAND} [OPTIONS]\n", g_prog_name);
	if (g_prog_desc != NULL)
		printf("%s", g_prog_desc);

	printf("\n");
	printf(START_SPACE "Help Document: README.md\n");
	printf(START_SPACE "Version: %s\n", CLI_VERSION);
	printf("\n");
	printf(START_SPACE "Generic Params:\n\n");

	memset(&ctx, 0, sizeof(struct arg_ctx));
	get_parse_args(&ctx, NULL);
	global_arg_len = ctx.size;

	__print_arg_list(&ctx, START_SPACE, max_len, global_arg_len);

	free(ctx.arg);

	printf("\n");

	printf(START_SPACE "Available COMMAND:\n\n");
	for (i = 0; i < g_sub_cmd_list_len; i++) {
		printf(START_SPACE " %s", g_sub_cmd_list[i]->name);
		for (j = strlen(g_sub_cmd_list[i]->name); j < max_len + 1; j++)
			printf(" ");
		printf("%s\n", g_sub_cmd_list[i]->help_str ? g_sub_cmd_list[i]->help_str : "");

		if (g_sub_cmd_list[i]->arg_list != NULL) {
			memset(&ctx, 0, sizeof(struct arg_ctx));
			get_parse_args(&ctx, g_sub_cmd_list[i]->arg_list);
			__print_arg_list(&ctx, START_SPACE START_SPACE, max_len, ctx.size - global_arg_len);
			free(ctx.arg);
			printf("\n");
		}
	}

	printf("\n");
}

void set_prog_desc(const char *desc)
{
	g_prog_desc = desc;
}

void register_global_args(const char *args)
{
	g_args = args;
}

void register_sub_cmd_args(struct sub_cmd **cmd_list, int cmd_list_len)
{
	g_sub_cmd_list = cmd_list;
	g_sub_cmd_list_len = cmd_list_len;
}

int do_cli_process(int argc, const char *argv[])
{
	struct sub_cmd *cmd;

	g_prog_name = argv[0];

	if (argc < 2)
		goto err;

	if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
		show_help();
		return 0;
	}

	cmd = find_sub_cmd(argv[1]);
	if (!cmd) {
		fprintf(stderr, "Error: not found sub cmd %s.\n", argv[1]);
		goto err;
	}

	return do_sub_cmd(cmd, argc - 1, argv + 1);

err:
	show_help();
	return -1;
}

const char *get_arg_by_name(void *ctx, const char *name)
{
	int i = 0;
	struct arg_ctx *pctx = (struct arg_ctx *)ctx;

	for (i = 0; i < pctx->size; i++) {
		if (strcmp(name, pctx->item_list[i].full_name))
			continue;

		/**
		 * if not accessed, use default val.
		 */
		if (pctx->item_list[i]._accessed) {
			if (pctx->item_list[i].arg_required) {
				return pctx->item_list[i].val;
			} else {
				/**
				 * No require value means it is a bool value.
				 * if accessed return 1;
				 */
				return "1";
			}
		} else {
			/**
			 * if not accessed, use default val.
			 */
			return pctx->item_list[i]._default_val;
		}
	}

	/* only dev stage bug would be here */
	printf("The parameter %s is not in the parsing parameter list of the module.", name);
	printf("Module can accept parameters:");
	for (i = 0; i < pctx->size; i++)
		printf(" %s", pctx->item_list[i].full_name);
	printf("\n");

	return NULL;
}

int set_arg_by_name(void *ctx, const char *name, const char *value)
{
	struct arg_ctx *pctx = ctx;

	if (!pctx || !name || !value)
		return -EINVAL;

	for (int i = 0; i < pctx->size; i++) {
		struct arg_parse_item *item = &pctx->item_list[i];

		if (strcmp(name, item->full_name) != 0)
			continue;

		if (item->arg_required) {
			char *new_value = strdup(value);

			if (!new_value)
				return -ENOMEM;

			if (item->_accessed && item->val)
				free(item->val);

			item->val = new_value;
			item->_accessed = true;
			return 0;
		}

		if (strcmp(value, "1") == 0) {
			item->_accessed = true;
			return 0;
		}

		if (strcmp(value, "0") == 0) {
			item->_accessed = false;
			return 0;
		}

		return -EINVAL;
	}

	return -ENOENT;
}

bool cli_arg_is_null_default(const char *arg_value)
{
	return arg_value && strcmp(arg_value, "null") == 0;
}

static int find_arg_parse_item(struct arg_parse_item *item, char *name)
{
	int i, len = sizeof(arg_parse_item_list) / sizeof(struct arg_parse_item);
	for (i = 0; i < len; i++) {
		if (strcmp(name, arg_parse_item_list[i].full_name))
			continue;

		memcpy(item, &arg_parse_item_list[i], sizeof(struct arg_parse_item));
		return 0;
	}
	return -1;
}

#define CLI_CMD_MAX_NAME_SIZE 128

static struct sub_cmd *find_sub_cmd(const char *name)
{
	int i;
	for (i = 0; i < g_sub_cmd_list_len; i++) {
		if (strncmp(g_sub_cmd_list[i]->name, name, CLI_CMD_MAX_NAME_SIZE))
			continue;
		return g_sub_cmd_list[i];
	}
	return NULL;
}

static int check_args_duplicated(struct arg_parse_item *item, int size)
{
	/* Only check conflicts for letter short names; ignore NO_SINGLE_NAME and non-letters */
	bool lower_mask[26] = { 0 };
	bool upper_mask[26] = { 0 };
	int i = 0;
	for (i = 0; i < size; i++) {
		int sn = item[i].single_name;
		if (sn == NO_SINGLE_NAME)
			continue;
		if (sn >= 'a' && sn <= 'z') {
			int idx = sn - 'a';
			if (lower_mask[idx]) {
				printf("The parameter %s has the same single name as the other parameters and cannot be resolved\n", item[i].full_name);
				for (int j = 0; j < size; j++)
					if (item[j].single_name == sn)
						printf(" %s -> %c\n", item[j].full_name, sn);
				return -1;
			}
			lower_mask[idx] = 1;
		} else if (sn >= 'A' && sn <= 'Z') {
			int idx = sn - 'A';
			if (upper_mask[idx]) {
				printf("The parameter %s has the same single name as the other parameters and cannot be resolved\n", item[i].full_name);
				for (int j = 0; j < size; j++)
					if (item[j].single_name == sn)
						printf(" %s -> %c\n", item[j].full_name, sn);
				return -1;
			}
			upper_mask[idx] = 1;
		} else {
			/* non-letter short names are auto-assigned and allowed to repeat */
			continue;
		}
	}
	return 0;
}

char **get_single_list_args(const char *list_arg, int *size)
{
	char *arg_copy;
	char *token;
	char **result;
	int count = 0;
	int i = 0;

	if (size)
		*size = 0;

	if (!list_arg || list_arg[0] == '\0')
		return NULL;

	arg_copy = strdup(list_arg);
	if (!arg_copy)
		return NULL;

	token = strtok(arg_copy, ",");
	while (token != NULL) {
		count++;
		token = strtok(NULL, ",");
	}

	free(arg_copy);
	arg_copy = strdup(list_arg);
	if (!arg_copy)
		return NULL;

	if (count == 0) {
		free(arg_copy);
		return NULL;
	}

	result = calloc(count, sizeof(char *));
	if (!result) {
		free(arg_copy);
		return NULL;
	}

	token = strtok(arg_copy, ",");

	while (token != NULL) {
		result[i] = strdup(token);
		if (!result[i]) {
			free(arg_copy);
			free_single_list_args(result, i);
			return NULL;
		}
		token = strtok(NULL, ",");
		i++;
	}

	if (size)
		*size = count;
	free(arg_copy);
	return result;
}

void free_single_list_args(char *list_arg[], int size)
{
	if (!list_arg)
		return;
	for (int i = 0; i < size; i++)
		if (list_arg[i])
			free(list_arg[i]);
	free(list_arg);
}

static int get_parse_args(struct arg_ctx *ctx, const char *arg_list)
{
	char *pos;
	struct arg_parse_item *item = ctx->item_list;
	int count = ctx->size;
	if (arg_list == NULL) {
		ctx->arg = strdup(g_args);
	} else {
		/* Concat the arg of global and the arg of sub cmd */
		ctx->arg = (char *)malloc(strlen(arg_list) + 1 + strlen(g_args) + 1);
		if (!ctx->arg)
			return -1;

		strcpy(ctx->arg, arg_list);
		ctx->arg[strlen(arg_list)] = ' ';
		strcpy(ctx->arg + strlen(arg_list) + 1, g_args);
		ctx->arg[strlen(arg_list) + 1 + strlen(g_args)] = '\0';
	}

	/* split with space */
	char *name = strtok(ctx->arg, " ");
	while (name != NULL) {
		if ((pos = strchr(name, '=')) != NULL)
			*pos = '\0';

		if (find_arg_parse_item(&item[count], name)) {
			fprintf(stderr, "not support arg type: \"%s\", check arg_parse_item_list\n", name);
			exit(-1);
		}

		if (pos)
			*pos = '=';
		else
			item[count]._required = 1;

		/* Not require value, and default to 1 */
		if (!item[count].arg_required && (pos && *(pos + 1) == '1'))
			item[count]._accessed = 1;
		/* No require value, and no default value, set default to 0 */
		else if (!item[count].arg_required && (!pos || *(pos + 1) != '1'))
			item[count]._default_val = "0";
		/* Require value, and has default value, set default val */
		else if (item[count].arg_required && pos)
			item[count]._default_val = pos + 1;

		count += 1;
		name = strtok(NULL, " ");
	}

	ctx->size = count;

	return check_args_duplicated(ctx->item_list, ctx->size);
}

static int do_sub_cmd(struct sub_cmd *cmd, int argc, const char *argv[])
{
	struct arg_ctx *ctx = NULL;
	struct option *lopt = NULL;
	char *lopt_str = NULL;

	int i, ret = -1, count = 0;
	int c;

	ctx = (struct arg_ctx *)calloc(1, sizeof(struct arg_ctx));
	if (!ctx) {
		fprintf(stderr, "ctx alloc failed.\n");
		return -1;
	}

	if (get_parse_args(ctx, cmd->arg_list)) {
		fprintf(stderr, "fatal error: parse_args() failed.\n");
		goto quit;
	}

	lopt = (struct option *)calloc(ctx->size + 1, sizeof(struct option));
	if (!lopt) {
		fprintf(stderr, "fatal error: alloc options failed.\n");
		goto quit;
	}

	lopt_str = (char *)malloc(ctx->size * 2 + 1);
	if (!lopt_str) {
		fprintf(stderr, "fatal error: alloc opt_str failed.\n");
		goto quit;
	}

	memset(lopt_str, 0, ctx->size * 2 + 1);

	/* Auto-assign single_name when it's 0, skipping ASCII letters [A-Z][a-z]. */
	{
		bool used_vals[256] = { false };
		int auto_val = 1;

		/* mark existing non-zero values as used */
		for (i = 0; i < ctx->size; i++) {
			unsigned int v = (unsigned char)ctx->item_list[i].single_name;
			if (v != 0)
				used_vals[v] = true;
		}

		/* assign sequential non-letter values starting from 1 */
		for (i = 0; i < ctx->size; i++) {
			if (ctx->item_list[i].single_name != 0)
				continue;
			while (auto_val <= 255 && (used_vals[auto_val] || (auto_val >= 'A' && auto_val <= 'Z') || (auto_val >= 'a' && auto_val <= 'z'))) {
				auto_val++;
			}
			if (auto_val > 255) {
				fprintf(stderr, "fatal error: no available single_name to assign.\n");
				goto quit;
			}
			ctx->item_list[i].single_name = (char)auto_val;
			used_vals[auto_val] = true;
			auto_val++;
		}
	}

	for (i = 0; i < ctx->size; i++) {
		lopt[i].name = ctx->item_list[i].full_name;
		lopt[i].val = ctx->item_list[i].single_name;
		lopt[i].has_arg = ctx->item_list[i].arg_required;
		lopt_str[count++] = lopt[i].val;
		if (lopt[i].has_arg)
			lopt_str[count++] = ':';
	}

	lopt_str[count++] = '\0';
	optind = 1;

	while ((c = getopt_long(argc, (char *const *)argv, lopt_str, lopt, &count)) != -1) {
		if (c == '?' || c == ':')
			goto quit;

		for (i = 0; i < ctx->size; i++) {
			if (c != (int)ctx->item_list[i].single_name)
				continue;
			ctx->item_list[i]._accessed = 1;
			if (ctx->item_list[i].arg_required)
				ctx->item_list[i].val = strdup(optarg);
		}
	}

	if (atoi(get_arg_by_name(ctx, "help")) == 1) {
		show_sub_cmd_help(cmd);
		ret = 0;
		goto quit;
	}

	const char *config_path = get_arg_by_name(ctx, "config");
	if (!cli_arg_is_null_default(config_path)) {
		struct cli_config *config = cli_config_init(NULL);

		load_config(config, config_path);
		struct cli_config_item *item;
		fprintf(stderr, "use config file [ %s ]\n", config_path);
		LL_FOREACH(config->items, item)
		{
			for (i = 0; i < ctx->size; i++) {
				if (strncmp(ctx->item_list[i].full_name, item->name, strlen(ctx->item_list[i].full_name)))
					continue;

				if (ctx->item_list[i]._accessed && ctx->item_list[i].arg_required)
					free(ctx->item_list[i].val);

				ctx->item_list[i]._accessed = 1;
				if (ctx->item_list[i].arg_required) {
					ctx->item_list[i].val = strdup(item->value);
				} else {
					if (strncmp("false", item->value, strlen("false")) == 0)
						ctx->item_list[i]._accessed = 0;
				}
				break;
			}
		}

		cli_config_destroy(config);
	}

	int duration = atoi(get_arg_by_name(ctx, "duration"));
	if (duration)
		alarm(duration);

	if (open_cli_raw_output(atoi(get_arg_by_name(ctx, "verbose"))))
		goto quit;

	for (i = 0; i < ctx->size; i++) {
		if (ctx->item_list[i]._required && !ctx->item_list[i]._accessed) {
			fprintf(stderr, "Error: arg \"%s\" required but not present\n", ctx->item_list[i].full_name);
			goto quit;
		}
	}

	ret = cmd->func(ctx);

quit:
	if (ctx) {
		for (i = 0; i < ctx->size; i++)
			if (ctx->item_list[i]._accessed)
				free(ctx->item_list[i].val);
		free(ctx->arg);
		free(ctx);
	}
	if (lopt)
		free(lopt);
	if (lopt_str)
		free(lopt_str);

	close_cli_raw_output();

	return ret;
}
