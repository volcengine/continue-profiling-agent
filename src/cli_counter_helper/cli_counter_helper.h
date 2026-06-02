// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef __CLI_COUNTER_HELPER_H__
#define __CLI_COUNTER_HELPER_H__

#include <stdint.h>
struct cli_counter;

/**
 * Counter category for unit selection.
 *
 * CLI_COUNTER_TYPE_TIME_NS uses time units (ns/us/ms/s) with a 1000 step.
 * CLI_COUNTER_TYPE_SIZE uses size units (B/KB/MB/GB/TB/PB) with a 1024 step.
 */
enum cli_counter_type {
	CLI_COUNTER_TYPE_TIME_NS = 0,
	CLI_COUNTER_TYPE_SIZE = 1,
};

/**
 * Create a counter instance for dynamic range binning.
 *
 * @param map_name Optional label shown as a prefix when printing.
 * @param type Counter category (time in ns or size in bytes).
 * @return Pointer to counter on success, NULL on failure.
 */
struct cli_counter *cli_counter_init(const char *map_name, enum cli_counter_type type);

/**
 * Destroy the counter and free internal memory.
 *
 * @param counter Pointer to the counter to destroy.
 */
void cli_counter_destroy(struct cli_counter *counter);

/**
 * Add one sample value to the counter.
 *
 * Value 0 is treated as 1 to fit into the first bin [1-2].
 *
 * @param counter Counter instance.
 * @param value Sample value to record.
 * @return 0 on success, non-zero on failure.
 */
int cli_counter_add(struct cli_counter *counter, uint64_t value);

/**
 * Print all non-empty bins and MIN/MAX/AVG via CLI_OUTPUT.
 *
 * @param counter Counter instance to print.
 */
void cli_counter_print(struct cli_counter *counter);

/**
 * Clear counts and stats without freeing allocated bins.
 *
 * This avoids repeated allocations across reuse cycles.
 *
 * @param counter Counter instance to clear.
 */
void cli_counter_clear(struct cli_counter *counter);

#endif
