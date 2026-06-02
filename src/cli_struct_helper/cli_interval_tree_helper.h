// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef __CLI_INTERVAL_TREE_HELPER_H__
#define __CLI_INTERVAL_TREE_HELPER_H__

#include <stddef.h>
#include <stdlib.h>

/**
 * @file cli_interval_tree_helper.h
 * @brief Interval tree wrapper for sparse address-range lookups.
 */

/**
 * struct interval_tree - opaque interval tree object.
 */
struct interval_tree;

/**
 * cli_interval_tree_init - allocate an empty interval tree.
 *
 * Return: new interval tree on success or %NULL on failure.
 */
struct interval_tree *cli_interval_tree_init(void);

/**
 * cli_interval_tree_node_count - query node count for a tree.
 * @tree: interval tree instance.
 *
 * Return: number of nodes currently stored.
 */
unsigned long cli_interval_tree_node_count(struct interval_tree *tree);

/**
 * cli_interval_tree_add - insert one interval and its payload.
 * @tree: interval tree instance.
 * @start: interval start address (inclusive).
 * @end: interval end address (inclusive).
 * @item: payload pointer to store in the node.
 */
void cli_interval_tree_add(struct interval_tree *tree, unsigned long start, unsigned long end, void *item);

/**
 * cli_interval_tree_search - search interval that contains @addr.
 * @tree: interval tree instance.
 * @addr: address to locate.
 * @start: optional output for matched interval start.
 * @end: optional output for matched interval end.
 *
 * Return: payload of matched interval, or %NULL if no interval covers @addr.
 */
void *cli_interval_tree_search(struct interval_tree *tree, unsigned long addr, unsigned long *start, unsigned long *end);

/**
 * cli_interval_tree_destroy - destroy an interval tree and all nodes.
 * @tree: interval tree instance to free.
 */
void cli_interval_tree_destroy(struct interval_tree *tree);

#endif /* __CLI_INTERVAL_TREE_HELPER_H__ */
