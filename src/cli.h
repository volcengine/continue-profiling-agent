// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CLI_H
#define CLI_H

#include <errno.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <endian.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <cpa_bpf.h>
#include <trace_helpers.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "cli_output.h"
#include "cli_common.h"
#include "cli_cmd_helper.h"
#include "cli_stackmap.h"

/**
 * @file cli.h
 * @brief Public CLI entry and generated sub-command declarations.
 */

/**
 * DEFINE_SUB_CMD - expand command handler prototype for one generated module.
 * @module: module name token from @auto/gen_modules.h.
 */
#define DEFINE_SUB_CMD(module) int SUB_CMD_FUNC(module)(void *ctx);
#include <auto/gen_modules.h>
#undef DEFINE_SUB_CMD

/**
 * DEFINE_SUB_CMD - expand command metadata declaration for one generated module.
 * @module: module name token from @auto/gen_modules.h.
 */
#define DEFINE_SUB_CMD(module) extern struct sub_cmd sub_cmd_##module;
#include <auto/gen_modules.h>
#undef DEFINE_SUB_CMD

#endif /* CLI_H */
