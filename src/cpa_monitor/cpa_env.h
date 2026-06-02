// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CPA_ENV_H
#define CPA_ENV_H

#include "cli.h"

/**
 * @file cpa_env.h
 * @brief Environment variable helpers for capture command arguments.
 */

/**
 * cpa_env_should_parse - decide whether user-space parsing stays enabled
 * @env_name: environment name derived for the current sample
 *
 * Return: true when user-space unwind/parsing should continue for @env_name.
 */
bool cpa_env_should_parse(const char *env_name);

/**
 * cpa_env_record_num - return number of configured environment names
 *
 * Return: count of configured environment variable names.
 */
int cpa_env_record_num(void);

/**
 * cpa_get_record_env - return configured environment names to record
 * @size: output length of the returned array
 *
 * Return: pointer array owned by the environment cache.
 */
char **cpa_get_record_env(int *size);

#endif /* CPA_ENV_H */
