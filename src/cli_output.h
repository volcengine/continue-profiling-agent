// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CLI_OUTPUT_H
#define CLI_OUTPUT_H

#include <stdbool.h>
#include <stdio.h>

/**
 * @file cli_output.h
 * @brief Raw CLI output helpers with optional verbose mode.
 */

/**
 * enum raw_output_level - output severity/verbosity level.
 * @RAW_OUTPUT_ERROR: route output to standard error.
 * @RAW_OUTPUT_COMMON: always visible normal output.
 * @RAW_OUTPUT_VERBOSE: printed only when verbose mode is enabled.
 */
enum raw_output_level {
	RAW_OUTPUT_ERROR = 0,
	RAW_OUTPUT_COMMON,
	RAW_OUTPUT_VERBOSE,
};

/**
 * open_cli_raw_output - initialize global output context.
 * @verbose: enable verbose output when non-zero.
 * @return: 0 on success, negative on failure.
 */
int open_cli_raw_output(bool verbose);

/**
 * close_cli_raw_output - release output context and close non-stdout descriptors.
 */
void close_cli_raw_output(void);

/**
 * cli_raw_output - print a formatted log line to stderr or stdout.
 * @level: one of @RAW_OUTPUT_ERROR, @RAW_OUTPUT_COMMON, @RAW_OUTPUT_VERBOSE.
 * @end: append newline when true.
 * @format: printf-compatible format string.
 */
void cli_raw_output(int level, bool end, const char *format, ...);

/* Output one error line to stderr. */
#define CLI_ERROR(fmt, ...) cli_raw_output(RAW_OUTPUT_ERROR, true, fmt, ##__VA_ARGS__)
/* Output without a trailing newline. */
#define CLI_OUTPUT_NO_END(fmt, ...) cli_raw_output(RAW_OUTPUT_COMMON, false, fmt, ##__VA_ARGS__)
/* Output one common line. */
#define CLI_OUTPUT(fmt, ...) cli_raw_output(RAW_OUTPUT_COMMON, true, fmt, ##__VA_ARGS__)
/* Output verbose text without a trailing newline. */
#define CLI_VERBOSE_NO_END(fmt, ...) cli_raw_output(RAW_OUTPUT_VERBOSE, false, fmt, ##__VA_ARGS__)
/* Output one verbose line when verbose mode is enabled. */
#define CLI_VERBOSE(fmt, ...) cli_raw_output(RAW_OUTPUT_VERBOSE, true, fmt, ##__VA_ARGS__)

#endif /* CLI_OUTPUT_H */
