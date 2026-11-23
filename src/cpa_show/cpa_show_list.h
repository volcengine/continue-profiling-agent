// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CPA_SHOW_LIST_H
#define CPA_SHOW_LIST_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

struct cli_stackmap_record_map;
struct stackmap_record;
struct metadata;

/*
 * Write the COREDUMP (@exits false) or EXIT NONZERO samples of @output_num
 * records from @record on to --output_prof (default cpa_core_* / cpa_exit_*).
 * @filter_func returns true for a sample to skip.  0 or -1.
 */
int cpa_show_list(void *ctx, bool exits, bool (*filter_func)(struct metadata *data), const char *read_file,
		  struct cli_stackmap_record_map *map, struct stackmap_record *record, int output_num,
		  uint64_t starttime, pid_t container_pid);

#endif
