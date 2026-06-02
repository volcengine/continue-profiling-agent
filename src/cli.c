// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include <cli.h>
#include <libelf.h>

/**
 * Parameter Parse Format:
 * If there is no equal sign, this parameter must be present. If it has an equal sign, it means that the parameter
 * will take the value after the equal sign as the default value if it does not.
 * If the parameter itself does not require a value, the absence of an equal sign or equal to 0 means false by default,
 * and the presence of equal to 1 means true by default.
 *
 * For example:
 * 
 * Arg "config": arg_required = true (define in arg_parse_item_list)
 * 	"config=/tmp/cpa.yaml" means that if there is no config parameter, /tmp/cpa.yaml is the default
 * 	"config" indicates that the config parameter must be present.
 *
 * Arg "verbose": arg_required = false (define in arg_parse_item_list)
 * 	"verbose" indicates that the default value is false
 * 	"verbose=0" indicates that the default value is false
 * 	"verbose=1" indicates that the default value is true
 */
#define GLOBAL_ARGS "duration=0 verbose=0 help=0 btf_path=null config=null"

int SUB_CMD_FUNC(help)(void *ctx);
int SUB_CMD_FUNC(version)(void *ctx);

SUB_CMD(help, NULL, "show help message for this program.");

SUB_CMD(version, NULL, "show version.");
/**
 * SUB_CMD macro second param format same as GLOBAL_ARGS.
 * See "Parameter Parse Format"
 */
struct sub_cmd *sub_cmd_list[] = {
#define DEFINE_SUB_CMD(module) &sub_cmd_##module,

#include <auto/gen_modules.h>

	DEFINE_SUB_CMD(help) DEFINE_SUB_CMD(version)

#undef DEFINE_SUB_CMD
};

void signal_handler(int signum)
{
	set_stop();
}

int main(int argc, const char *argv[])
{
	int ret = 0;

	if (signal(SIGINT, signal_handler) == SIG_ERR) {
		fprintf(stderr, "Error: register signal int handler failed. errno: %d.\n", errno);
		return -1;
	}

	if (signal(SIGALRM, signal_handler) == SIG_ERR) {
		fprintf(stderr, "Error: register signal alarm handler failed. errno: %d.\n", errno);
		return -1;
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "ELF library initialization failed: %s\n", elf_errmsg(-1));
		exit(EXIT_FAILURE);
	}

	register_global_args(GLOBAL_ARGS);

	register_sub_cmd_args(sub_cmd_list, sizeof(sub_cmd_list) / sizeof(struct sub_cmd *));

	ret = do_cli_process(argc, argv);

	if (get_bpf_mask())
		free_bpf();

	return ret;
}

int SUB_CMD_FUNC(help)(void *ctx)
{
	show_help();
	return 0;
}

int SUB_CMD_FUNC(version)(void *ctx)
{
	printf("continue-profiling-agent %s\n", CLI_VERSION);
	return 0;
}
