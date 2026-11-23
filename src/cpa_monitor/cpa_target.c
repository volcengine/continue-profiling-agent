// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

/*
 * Process-selection argument parsing.  Kept free of BPF and CLI dependencies
 * so the rules can be unit tested on their own.
 *
 * Selection model: different options are ANDed, comma separated values inside
 * one option are ORed.  A single --pid (optionally with --thread_comm) keeps
 * the historical scalar filter; everything else goes through target_ctl.
 */

#include "cpa_target.h"

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool arg_set(const char *value)
{
	return value && value[0] && strcmp(value, "null") != 0;
}

static int fail(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;

	if (err && errlen) {
		va_start(ap, fmt);
		vsnprintf(err, errlen, fmt, ap);
		va_end(ap);
	}
	return -EINVAL;
}

static int parse_positive(const char *text, long max, long *out)
{
	char *end = NULL;
	long value;

	if (!text || !text[0])
		return -EINVAL;
	errno = 0;
	value = strtol(text, &end, 10);
	if (errno || end == text || *end != '\0' || value <= 0 || value > max)
		return -EINVAL;
	*out = value;
	return 0;
}

/*
 * Split @list on ',' and hand every trimmed, non-empty element to @fn.
 * Returns the callback's first error, or -EINVAL for an empty element.
 */
static int for_each_item(const char *list, char *err, size_t errlen,
			 const char *opt,
			 int (*fn)(const char *item, void *ctx, char *err,
				   size_t errlen),
			 void *ctx)
{
	char *copy = strdup(list);
	char *save = NULL, *item;
	int ret = 0;

	if (!copy)
		return -ENOMEM;
	if (list[strlen(list) - 1] == ',' || list[0] == ',' ||
	    strstr(list, ",,")) {
		ret = fail(err, errlen, "--%s: empty value in '%s'", opt, list);
		goto out;
	}
	for (item = strtok_r(copy, ",", &save); item;
	     item = strtok_r(NULL, ",", &save)) {
		ret = fn(item, ctx, err, errlen);
		if (ret)
			break;
	}
out:
	free(copy);
	return ret;
}

static int add_pid(const char *item, void *ctx, char *err, size_t errlen)
{
	struct cpa_target_spec *spec = ctx;
	long pid;

	if (parse_positive(item, INT32_MAX, &pid))
		return fail(err, errlen, "--pid: invalid pid '%s'", item);
	if (spec->n_pids >= CPA_TARGET_MAX_PIDS)
		return fail(err, errlen, "--pid: at most %d pids",
			    CPA_TARGET_MAX_PIDS);
	for (int i = 0; i < spec->n_pids; i++)
		if (spec->pids[i] == (uint32_t)pid)
			return 0;
	spec->pids[spec->n_pids++] = (uint32_t)pid;
	return 0;
}

static int check_comm(const char *item, const char *opt, char *err,
		      size_t errlen)
{
	size_t len = strlen(item);

	if (len == 0)
		return fail(err, errlen, "--%s: empty name", opt);
	/* Exact matching on a truncated name would silently select others. */
	if (len >= CPA_TARGET_COMM_LEN)
		return fail(err, errlen,
			    "--%s: '%s' is longer than %d bytes; the kernel keeps "
			    "at most %d bytes of a process name",
			    opt, item, CPA_TARGET_COMM_LEN - 1,
			    CPA_TARGET_COMM_LEN - 1);
	return 0;
}

static int add_comm(const char *item, void *ctx, char *err, size_t errlen)
{
	struct cpa_target_spec *spec = ctx;
	int ret = check_comm(item, "comm", err, errlen);

	if (ret)
		return ret;
	if (spec->n_comms >= CPA_TARGET_MAX_COMMS)
		return fail(err, errlen, "--comm: at most %d names",
			    CPA_TARGET_MAX_COMMS);
	for (int i = 0; i < spec->n_comms; i++)
		if (strcmp(spec->comms[i], item) == 0)
			return 0;
	memset(spec->comms[spec->n_comms], 0, CPA_TARGET_COMM_LEN);
	memcpy(spec->comms[spec->n_comms], item, strlen(item));
	spec->n_comms++;
	return 0;
}

static int add_path(const char *item, char paths[][PATH_MAX], int *count,
		    int max, const char *opt, char *err, size_t errlen)
{
	if (*count >= max)
		return fail(err, errlen, "--%s: at most %d paths", opt, max);
	if (strlen(item) >= PATH_MAX)
		return fail(err, errlen, "--%s: path too long", opt);
	for (int i = 0; i < *count; i++)
		if (strcmp(paths[i], item) == 0)
			return 0;
	snprintf(paths[*count], PATH_MAX, "%s", item);
	(*count)++;
	return 0;
}

static int add_exe(const char *item, void *ctx, char *err, size_t errlen)
{
	struct cpa_target_spec *spec = ctx;

	if (item[0] != '/')
		return fail(err, errlen, "--exe: '%s' must be an absolute path",
			    item);
	return add_path(item, spec->exes, &spec->n_exes, CPA_TARGET_MAX_EXES,
			"exe", err, errlen);
}

static int add_cgroup(const char *item, void *ctx, char *err, size_t errlen)
{
	struct cpa_target_spec *spec = ctx;

	return add_path(item, spec->cgroups, &spec->n_cgroups,
			CPA_TARGET_MAX_CGROUPS, "cgroup", err, errlen);
}

static void append(char *buf, size_t len, const char *fmt, ...)
{
	size_t used = strlen(buf);
	va_list ap;

	if (used >= len)
		return;
	va_start(ap, fmt);
	vsnprintf(buf + used, len - used, fmt, ap);
	va_end(ap);
}

static void build_summary(struct cpa_target_spec *spec)
{
	char *s = spec->summary;
	size_t n = sizeof(spec->summary);

	s[0] = '\0';
	if (spec->mode == CPA_TARGET_LEGACY) {
		if (!spec->legacy_pid && !spec->legacy_thread_comm[0]) {
			append(s, n, "all processes");
			return;
		}
		if (spec->legacy_pid)
			append(s, n, "pid=%d ", spec->legacy_pid);
		if (spec->legacy_thread_comm[0])
			append(s, n, "thread_comm=%s ", spec->legacy_thread_comm);
		s[strlen(s) - 1] = '\0';
		return;
	}
	for (int i = 0; i < spec->n_pids; i++)
		append(s, n, "%s%u", i ? "," : "pid=", spec->pids[i]);
	for (int i = 0; i < spec->n_comms; i++)
		append(s, n, "%s%s", i ? "," : (s[0] ? " comm=" : "comm="),
		       spec->comms[i]);
	for (int i = 0; i < spec->n_exes; i++)
		append(s, n, "%s%s", i ? "," : (s[0] ? " exe=" : "exe="),
		       spec->exes[i]);
	for (int i = 0; i < spec->n_cgroups; i++)
		append(s, n, "%s%s", i ? "," : (s[0] ? " cgroup=" : "cgroup="),
		       spec->cgroups[i]);
	if (spec->container_pid)
		append(s, n, "%scontainer_pid=%d", s[0] ? " " : "",
		       spec->container_pid);
	if (spec->cgroup_recursive)
		append(s, n, " cgroup_recursive");
	if (spec->children)
		append(s, n, " children");
	if (spec->first_match)
		append(s, n, " first_match");
	else if (spec->new_only)
		append(s, n, " new_only");
	if (spec->startup_window_sec)
		append(s, n, " startup_window=%us", spec->startup_window_sec);
}

bool cpa_target_has_rules(const struct cpa_target_spec *spec)
{
	return spec->n_comms || spec->n_exes || spec->n_cgroups ||
	       spec->container_pid;
}

int cpa_target_parse(const struct cpa_target_raw *raw, struct cpa_target_spec *out,
		    char *err, size_t errlen)
{
	bool has_rules;
	int ret;

	if (!raw || !out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	if (err && errlen)
		err[0] = '\0';

	if (arg_set(raw->pid)) {
		/* "0" is the historical "all processes" default. */
		if (strcmp(raw->pid, "0") != 0) {
			ret = for_each_item(raw->pid, err, errlen, "pid", add_pid,
					    out);
			if (ret)
				return ret;
		}
	}
	if (arg_set(raw->comm)) {
		ret = for_each_item(raw->comm, err, errlen, "comm", add_comm, out);
		if (ret)
			return ret;
	}
	if (arg_set(raw->exe)) {
		ret = for_each_item(raw->exe, err, errlen, "exe", add_exe, out);
		if (ret)
			return ret;
	}
	if (arg_set(raw->cgroup)) {
		ret = for_each_item(raw->cgroup, err, errlen, "cgroup",
				    add_cgroup, out);
		if (ret)
			return ret;
	}
	if (arg_set(raw->container_pid)) {
		long pid;

		if (parse_positive(raw->container_pid, INT32_MAX, &pid))
			return fail(err, errlen, "--container_pid: invalid pid '%s'",
				    raw->container_pid);
		out->container_pid = (int)pid;
	}
	if (arg_set(raw->startup_window)) {
		long sec;

		if (parse_positive(raw->startup_window, 7 * 24 * 3600, &sec))
			return fail(err, errlen,
				    "--startup_window: expected seconds > 0, got '%s'",
				    raw->startup_window);
		out->startup_window_sec = (unsigned int)sec;
	}
	out->cgroup_recursive = raw->cgroup_recursive;
	out->children = raw->children;
	out->new_only = raw->new_only || raw->first_match;
	out->first_match = raw->first_match;

	has_rules = cpa_target_has_rules(out);

	if (arg_set(raw->thread_comm)) {
		ret = check_comm(raw->thread_comm, "thread_comm", err, errlen);
		if (ret)
			return ret;
		if (has_rules || out->n_pids > 1 || out->children ||
		    out->new_only || out->startup_window_sec)
			return fail(err, errlen,
				    "--thread_comm can only be combined with a single --pid");
		memcpy(out->legacy_thread_comm, raw->thread_comm,
		       strlen(raw->thread_comm));
	}

	if (out->n_pids && has_rules)
		return fail(err, errlen,
			    "--pid selects processes directly; it cannot be combined "
			    "with --comm/--exe/--cgroup/--container_pid");
	if (out->new_only && !has_rules)
		return fail(err, errlen,
			    "--%s needs at least one of --comm/--exe/--cgroup/--container_pid "
			    "to recognise the process when it starts",
			    raw->first_match ? "first_match" : "new_only");
	if (out->cgroup_recursive && !out->n_cgroups)
		return fail(err, errlen, "--cgroup_recursive requires --cgroup");
	/*
	 * Both select by cgroup; ANDing two cgroup subtrees is never what a user
	 * means, and --container_pid implies recursion that --cgroup may not.
	 */
	if (out->container_pid && (out->n_cgroups || out->cgroup_recursive))
		return fail(err, errlen,
			    "--container_pid already selects a cgroup; do not combine it "
			    "with --cgroup/--cgroup_recursive");

	if (!has_rules && out->n_pids <= 1 && !out->children) {
		if (out->startup_window_sec)
			return fail(err, errlen,
				    "--startup_window needs a rule based selection "
				    "(--comm/--exe/--cgroup/--container_pid) or --children");
		out->mode = CPA_TARGET_LEGACY;
		out->legacy_pid = out->n_pids ? (int)out->pids[0] : 0;
		out->n_pids = 0;
	} else {
		if (out->children && !has_rules && !out->n_pids)
			return fail(err, errlen, "--children needs --pid or a rule");
		out->mode = CPA_TARGET_DYNAMIC;
	}

	build_summary(out);
	return 0;
}

/* ------------------------------------------------------------ exit -- */

static int add_exit_comm(const char *item, void *ctx, char *err, size_t errlen)
{
	struct cpa_exit_spec *spec = ctx;
	int ret = check_comm(item, "exit_comm", err, errlen);

	if (ret)
		return ret;
	for (int i = 0; i < spec->n_comms; i++)
		if (strcmp(spec->comms[i], item) == 0)
			return 0;
	if (spec->n_comms >= CPA_TARGET_MAX_COMMS)
		return fail(err, errlen, "--exit_comm: at most %d names",
			    CPA_TARGET_MAX_COMMS);
	memset(spec->comms[spec->n_comms], 0, CPA_TARGET_COMM_LEN);
	memcpy(spec->comms[spec->n_comms], item, strlen(item));
	spec->n_comms++;
	return 0;
}

static int add_exit_pid(const char *item, void *ctx, char *err, size_t errlen)
{
	struct cpa_exit_spec *spec = ctx;
	long pid;

	if (parse_positive(item, INT32_MAX, &pid))
		return fail(err, errlen, "--exit_pid: invalid pid '%s'", item);
	for (int i = 0; i < spec->n_pids; i++)
		if (spec->pids[i] == (uint32_t)pid)
			return 0;
	if (spec->n_pids >= CPA_TARGET_MAX_PIDS)
		return fail(err, errlen, "--exit_pid: at most %d pids",
			    CPA_TARGET_MAX_PIDS);
	spec->pids[spec->n_pids++] = (uint32_t)pid;
	return 0;
}

static int add_exit_env_name(const char *item, void *ctx, char *err,
			     size_t errlen)
{
	struct cpa_exit_spec *spec = ctx;

	if (strlen(item) >= CPA_EXIT_ENV_NAME_LEN || strchr(item, '='))
		return fail(err, errlen,
			    "--exit_target_env_name: invalid name '%s' (no '=', "
			    "at most %d bytes)", item, CPA_EXIT_ENV_NAME_LEN - 1);
	for (int i = 0; i < spec->n_env_names; i++)
		if (strcmp(spec->env_names[i], item) == 0)
			return 0;
	if (spec->n_env_names >= CPA_EXIT_MAX_ENV_NAMES)
		return fail(err, errlen, "--exit_target_env_name: at most %d names",
			    CPA_EXIT_MAX_ENV_NAMES);
	snprintf(spec->env_names[spec->n_env_names++], CPA_EXIT_ENV_NAME_LEN,
		 "%s", item);
	return 0;
}

static int add_env_value(const char *opt, const char *item,
			 char list[][CPA_EXIT_ENV_VALUE_LEN], int *n, char *err,
			 size_t errlen)
{
	if (strlen(item) >= CPA_EXIT_ENV_VALUE_LEN)
		return fail(err, errlen, "--%s: '%s' is longer than %d bytes",
			    opt, item, CPA_EXIT_ENV_VALUE_LEN - 1);
	for (int i = 0; i < *n; i++)
		if (strcmp(list[i], item) == 0)
			return 0;
	if (*n >= CPA_EXIT_MAX_ENV_VALUES)
		return fail(err, errlen, "--%s: at most %d values", opt,
			    CPA_EXIT_MAX_ENV_VALUES);
	snprintf(list[(*n)++], CPA_EXIT_ENV_VALUE_LEN, "%s", item);
	return 0;
}

static int add_exit_env_value(const char *item, void *ctx, char *err,
			      size_t errlen)
{
	struct cpa_exit_spec *spec = ctx;

	return add_env_value("exit_target_env_values", item, spec->env_values,
			     &spec->n_env_values, err, errlen);
}

static int add_exit_env_prefix(const char *item, void *ctx, char *err,
			       size_t errlen)
{
	struct cpa_exit_spec *spec = ctx;

	return add_env_value("exit_target_env_value_prefix", item,
			     spec->env_prefixes, &spec->n_env_prefixes, err,
			     errlen);
}

int cpa_exit_parse(const struct cpa_exit_raw *raw, struct cpa_exit_spec *out,
		   char *err, size_t errlen)
{
	static const struct {
		size_t raw_off;
		const char *opt;
		int (*add)(const char *, void *, char *, size_t);
	} items[] = {
		{ offsetof(struct cpa_exit_raw, comm), "exit_comm", add_exit_comm },
		{ offsetof(struct cpa_exit_raw, pid), "exit_pid", add_exit_pid },
		{ offsetof(struct cpa_exit_raw, env_name), "exit_target_env_name", add_exit_env_name },
		{ offsetof(struct cpa_exit_raw, env_values), "exit_target_env_values", add_exit_env_value },
		{ offsetof(struct cpa_exit_raw, env_value_prefix), "exit_target_env_value_prefix", add_exit_env_prefix },
	};

	if (!raw || !out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	if (err && errlen)
		err[0] = '\0';

	for (size_t i = 0; i < sizeof(items) / sizeof(items[0]); i++) {
		const char *value = *(const char *const *)((const char *)raw + items[i].raw_off);
		int ret;

		if (!arg_set(value))
			continue;
		ret = for_each_item(value, err, errlen, items[i].opt, items[i].add, out);
		if (ret)
			return ret;
	}
	if (out->n_comms && out->n_pids)
		return fail(err, errlen,
			    "--exit_pid selects processes directly; it cannot be "
			    "combined with --exit_comm");
	if (out->n_env_names && !out->n_env_values && !out->n_env_prefixes)
		return fail(err, errlen,
			    "--exit_target_env_name needs --exit_target_env_values "
			    "or --exit_target_env_value_prefix");
	if (!out->n_env_names && (out->n_env_values || out->n_env_prefixes))
		return fail(err, errlen,
			    "--exit_target_env_values / "
			    "--exit_target_env_value_prefix need "
			    "--exit_target_env_name");
	/* only an own selection has a moment of selection to read at */
	if (out->n_env_names && !cpa_exit_has_targets(out))
		return fail(err, errlen,
			    "--exit_target_env_name requires --exit_comm or "
			    "--exit_pid");
	return 0;
}
