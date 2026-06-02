// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CLI_CMD_HELPER_H
#define CLI_CMD_HELPER_H

#include <stdio.h>
#include <stdbool.h>

#ifndef CLI_VERSION
#define CLI_VERSION "1.0.0"
#endif

/**
 * SUB_CMD_FUNC - expand to subcommand entry symbol.
 * @module: subcommand name token.
 */
#define SUB_CMD_FUNC(module) sub_cmd_##module##_func

/**
 * SUB_CMD - define one generated sub_cmd descriptor.
 * @module: module name token from @auto/gen_modules.h.
 * @arg: argument placeholder string shown in help output.
 * @help: help text for command usage.
 */
#define SUB_CMD(module, arg, help)                                                                                                                                                                                                                             \
	struct sub_cmd sub_cmd_##module = {                                                                                                                                                                                                                    \
		.name = #module,                                                                                                                                                                                                                               \
		.arg_list = arg,                                                                                                                                                                                                                               \
		.help_str = help,                                                                                                                                                                                                                              \
		.func = SUB_CMD_FUNC(module),                                                                                                                                                                                                                  \
	}

/**
 * @file cli_cmd_helper.h
 * @brief Generic command-line helper declarations and subcommand registration.
 */

/**
 * struct sub_cmd - command metadata used by CLI table.
 * @name: subcommand name.
 * @arg_list: argument usage suffix.
 * @help_str: help text.
 * @func: handler entry point.
 */
struct sub_cmd {
	const char *name;
	const char *arg_list;
	const char *help_str;
	int (*func)(void *);
};

/**
 * register_global_args - add args shared by all subcommands.
 * @global_args: command line options string to append to parser.
 */
void register_global_args(const char *global_args);

/**
 * register_sub_cmd_args - register all subcommands in parser.
 * @cmd_list: array of subcommand descriptors.
 * @cmd_list_len: number of entries in @cmd_list.
 */
void register_sub_cmd_args(struct sub_cmd **cmd_list, int cmd_list_len);

/**
 * do_cli_process - parse CLI args and dispatch selected subcommand.
 * @argc: argument count from main().
 * @argv: argument vector from main().
 * @return: selected subcommand exit status.
 */
int do_cli_process(int argc, const char *argv[]);

/**
 * get_arg_by_name - fetch argument value from context.
 * @ctx: command parser context.
 * @name: option name.
 * @return: pointer to option value, or %NULL when absent.
 */
const char *get_arg_by_name(void *ctx, const char *name);

/**
 * set_arg_by_name - override one parsed argument in context.
 * @ctx: command parser context.
 * @name: option name.
 * @value: replacement value.
 * @return: 0 on success, negative on failure.
 */
int set_arg_by_name(void *ctx, const char *name, const char *value);

/**
 * cli_arg_is_null_default - check whether one CLI string is the sentinel "null".
 * @arg_value: parsed argument value.
 * @return: true when @arg_value equals "null".
 */
bool cli_arg_is_null_default(const char *arg_value);

/**
 * get_single_list_args - split comma separated list into array.
 * @list_arg: user provided list string.
 * @size: output count.
 * @return: array of duplicated strings or %NULL.
 */
char **get_single_list_args(const char *list_arg, int *size);

/**
 * free_single_list_args - release array returned by @get_single_list_args.
 * @list_arg: array returned by @get_single_list_args.
 * @size: number of elements.
 */
void free_single_list_args(char *list_arg[], int size);

/**
 * show_help - print generated help text.
 */
void show_help(void);

#endif /* CLI_CMD_HELPER_H */
