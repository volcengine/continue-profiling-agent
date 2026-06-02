// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include "cli_interval_tree_helper.h"

struct interval_node {
	unsigned long start;
	unsigned long end;
	unsigned long max_end;
	void *item;
	struct interval_node *left;
	struct interval_node *right;
};

struct interval_tree {
	struct interval_node *root;
	unsigned long count;
};

struct interval_tree *cli_interval_tree_init(void)
{
	struct interval_tree *tree;

	tree = malloc(sizeof(*tree));
	if (!tree)
		return NULL;

	tree->root = NULL;
	return tree;
}

unsigned long cli_interval_tree_node_count(struct interval_tree *tree)
{
	if (!tree)
		return 0;
	return tree->count;
}

static struct interval_node *create_interval_node(unsigned long start, unsigned long end, void *item)
{
	struct interval_node *node;

	node = malloc(sizeof(*node));
	if (!node)
		return NULL;

	node->start = start;
	node->end = end;
	node->max_end = end;
	node->item = item;
	node->left = NULL;
	node->right = NULL;

	return node;
}

static void update_max_end(struct interval_node *node)
{
	unsigned long max_end = node->end;

	if (node->left && node->left->max_end > max_end)
		max_end = node->left->max_end;
	if (node->right && node->right->max_end > max_end)
		max_end = node->right->max_end;

	node->max_end = max_end;
}

void cli_interval_tree_add(struct interval_tree *tree, unsigned long start, unsigned long end, void *item)
{
	struct interval_node **curr, *new_node;

	if (!tree || start > end)
		return;

	curr = &tree->root;
	new_node = create_interval_node(start, end, item);
	if (!new_node)
		return;

	tree->count++;

	while (*curr) {
		if (start < (*curr)->start)
			curr = &(*curr)->left;
		else
			curr = &(*curr)->right;
	}

	*curr = new_node;

	curr = &tree->root;
	while (*curr != new_node) {
		update_max_end(*curr);
		if (start < (*curr)->start)
			curr = &(*curr)->left;
		else
			curr = &(*curr)->right;
	}
}

void *cli_interval_tree_search(struct interval_tree *tree, unsigned long addr, unsigned long *start, unsigned long *end)
{
	struct interval_node *curr;

	if (!tree || !tree->root)
		return NULL;

	curr = tree->root;
	while (curr) {
		if (addr >= curr->start && addr <= curr->end) {
			if (start)
				*start = curr->start;
			if (end)
				*end = curr->end;
			return curr->item;
		}

		if (curr->left && curr->left->max_end >= addr) {
			curr = curr->left;
			continue;
		}

		curr = curr->right;
	}

	return NULL;
}

static void free_interval_tree(struct interval_node *root)
{
	struct interval_node **stack;
	int top = -1;
	int capacity = 128;
	struct interval_node *curr;

	if (!root)
		return;

	stack = malloc(sizeof(struct interval_node *) * capacity);
	if (!stack)
		return;

	stack[++top] = root;
	while (top >= 0) {
		curr = stack[top--];

		if (curr->left) {
			if (top + 1 >= capacity) {
				capacity *= 2;
				stack = realloc(stack, sizeof(struct interval_node *) * capacity);
				if (!stack)
					return;
			}
			stack[++top] = curr->left;
		}

		if (curr->right) {
			if (top + 1 >= capacity) {
				capacity *= 2;
				stack = realloc(stack, sizeof(struct interval_node *) * capacity);
				if (!stack)
					return;
			}
			stack[++top] = curr->right;
		}

		free(curr);
	}

	free(stack);
}

void cli_interval_tree_destroy(struct interval_tree *tree)
{
	if (!tree)
		return;

	free_interval_tree(tree->root);
	free(tree);
}
