# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

"""Unit tests for process-selection argument parsing (cpa_target.c)."""

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src/cpa_monitor"

HARNESS = r'''
#include "cpa_target.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static int failures;

#define EXPECT(cond, ...) do { \
	if (!(cond)) { \
		failures++; \
		printf("FAIL %s:%d: ", __FILE__, __LINE__); \
		printf(__VA_ARGS__); \
		printf("\n"); \
	} \
} while (0)

static int parse(struct cpa_target_raw raw, struct cpa_target_spec *spec,
		 char *err)
{
	return cpa_target_parse(&raw, spec, err, 256);
}

int main(void)
{
	struct cpa_target_spec s;
	char err[256];
	int ret;

	/* defaults: legacy, all processes */
	ret = parse((struct cpa_target_raw){ .pid = "0", .comm = "null" }, &s, err);
	EXPECT(ret == 0 && s.mode == CPA_TARGET_LEGACY && s.legacy_pid == 0,
	       "default %d %d", ret, s.mode);
	EXPECT(strcmp(s.summary, "all processes") == 0, "summary %s", s.summary);

	/* single pid keeps the scalar path */
	ret = parse((struct cpa_target_raw){ .pid = "1234" }, &s, err);
	EXPECT(ret == 0 && s.mode == CPA_TARGET_LEGACY && s.legacy_pid == 1234,
	       "single pid");

	/* thread comm alone and with one pid stays legacy */
	ret = parse((struct cpa_target_raw){ .thread_comm = "C2 CompilerThre" },
		    &s, err);
	EXPECT(ret == 0 && s.mode == CPA_TARGET_LEGACY &&
	       strcmp(s.legacy_thread_comm, "C2 CompilerThre") == 0,
	       "thread comm: %s", err);
	ret = parse((struct cpa_target_raw){ .pid = "7", .thread_comm = "x" },
		    &s, err);
	EXPECT(ret == 0 && s.legacy_pid == 7, "pid + thread comm");

	/* pid list and --children go dynamic */
	ret = parse((struct cpa_target_raw){ .pid = "1,2,2,3" }, &s, err);
	EXPECT(ret == 0 && s.mode == CPA_TARGET_DYNAMIC && s.n_pids == 3,
	       "pid list n=%d", s.n_pids);
	ret = parse((struct cpa_target_raw){ .pid = "9", .children = true }, &s,
		    err);
	EXPECT(ret == 0 && s.mode == CPA_TARGET_DYNAMIC && s.n_pids == 1,
	       "pid children");

	/* rule based selection */
	ret = parse((struct cpa_target_raw){ .comm = "java,jsvc" }, &s, err);
	EXPECT(ret == 0 && s.mode == CPA_TARGET_DYNAMIC && s.n_comms == 2 &&
	       !s.new_only, "comm list");
	ret = parse((struct cpa_target_raw){ .cgroup = "kubepods/pod1",
					   .cgroup_recursive = true,
					   .comm = "java", .first_match = true,
					   .startup_window = "60" }, &s, err);
	EXPECT(ret == 0 && s.first_match && s.new_only &&
	       s.startup_window_sec == 60 && s.n_cgroups == 1,
	       "cold start: %s", err);
	EXPECT(strstr(s.summary, "first_match") && strstr(s.summary, "comm=java"),
	       "summary %s", s.summary);
	ret = parse((struct cpa_target_raw){ .container_pid = "4321",
					   .comm = "app", .first_match = true },
		    &s, err);
	EXPECT(ret == 0 && s.container_pid == 4321, "container pid");
	ret = parse((struct cpa_target_raw){ .exe = "/opt/a,/opt/b",
					   .new_only = true }, &s, err);
	EXPECT(ret == 0 && s.n_exes == 2 && s.new_only && !s.first_match,
	       "exe new_only");

	/* rejected combinations */
	ret = parse((struct cpa_target_raw){ .first_match = true }, &s, err);
	EXPECT(ret == -EINVAL && strstr(err, "first_match"), "first_match alone");
	ret = parse((struct cpa_target_raw){ .pid = "1", .comm = "x" }, &s, err);
	EXPECT(ret == -EINVAL && strstr(err, "--pid"), "pid+comm");
	ret = parse((struct cpa_target_raw){ .pid = "1", .first_match = true },
		    &s, err);
	EXPECT(ret == -EINVAL, "pid+first_match");
	ret = parse((struct cpa_target_raw){ .comm = "abcdefghijklmnop" }, &s, err);
	EXPECT(ret == -EINVAL && strstr(err, "longer"), "comm too long: %s", err);
	ret = parse((struct cpa_target_raw){ .comm = "abcdefghijklmno" }, &s, err);
	EXPECT(ret == 0, "15 byte comm is fine");
	ret = parse((struct cpa_target_raw){ .comm = "a,,b" }, &s, err);
	EXPECT(ret == -EINVAL, "empty list item");
	ret = parse((struct cpa_target_raw){ .cgroup_recursive = true }, &s, err);
	EXPECT(ret == -EINVAL, "recursive without cgroup");
	ret = parse((struct cpa_target_raw){ .thread_comm = "x", .comm = "y" }, &s,
		    err);
	EXPECT(ret == -EINVAL, "thread comm + comm");
	ret = parse((struct cpa_target_raw){ .cgroup = "/a", .container_pid = "1",
					   .comm = "x" }, &s, err);
	EXPECT(ret == -EINVAL && strstr(err, "container_pid"),
	       "cgroup + container_pid");
	ret = parse((struct cpa_target_raw){ .container_pid = "1",
					   .cgroup_recursive = true }, &s, err);
	EXPECT(ret == -EINVAL, "container_pid + cgroup_recursive");
	ret = parse((struct cpa_target_raw){ .exe = "relative/app" }, &s, err);
	EXPECT(ret == -EINVAL, "relative exe");
	ret = parse((struct cpa_target_raw){ .pid = "-1" }, &s, err);
	EXPECT(ret == -EINVAL, "negative pid");
	ret = parse((struct cpa_target_raw){ .pid = "12a" }, &s, err);
	EXPECT(ret == -EINVAL, "garbage pid");
	ret = parse((struct cpa_target_raw){ .comm = "x", .startup_window = "0" },
		    &s, err);
	EXPECT(ret == -EINVAL, "zero window");
	ret = parse((struct cpa_target_raw){ .pid = "5", .startup_window = "3" },
		    &s, err);
	EXPECT(ret == -EINVAL, "window on legacy pid");
	ret = parse((struct cpa_target_raw){ .pid = "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17" },
		    &s, err);
	EXPECT(ret == -EINVAL, "too many pids");
	ret = parse((struct cpa_target_raw){ .new_only = true }, &s, err);
	EXPECT(ret == -EINVAL && strstr(err, "--new_only needs"),
	       "new_only alone: %s", err);
	ret = parse((struct cpa_target_raw){ .pid = "1,2", .new_only = true },
		    &s, err);
	EXPECT(ret == -EINVAL, "pid list + new_only");
	ret = parse((struct cpa_target_raw){ .pid = "1", .cgroup = "/a" }, &s,
		    err);
	EXPECT(ret == -EINVAL && strstr(err, "--pid"), "pid + cgroup");
	ret = parse((struct cpa_target_raw){ .pid = "1", .container_pid = "2" },
		    &s, err);
	EXPECT(ret == -EINVAL && strstr(err, "--pid"), "pid + container_pid");
	ret = parse((struct cpa_target_raw){ .pid = "1", .exe = "/bin/true" },
		    &s, err);
	EXPECT(ret == -EINVAL && strstr(err, "--pid"), "pid + exe");
	ret = parse((struct cpa_target_raw){ .pid = "1,2", .thread_comm = "x" },
		    &s, err);
	EXPECT(ret == -EINVAL && strstr(err, "--thread_comm"),
	       "thread comm + pid list");
	ret = parse((struct cpa_target_raw){ .pid = "1", .children = true,
					   .thread_comm = "x" }, &s, err);
	EXPECT(ret == -EINVAL && strstr(err, "--thread_comm"),
	       "thread comm + children");
	ret = parse((struct cpa_target_raw){ .thread_comm = "abcdefghijklmnop" },
		    &s, err);
	EXPECT(ret == -EINVAL, "thread comm too long");
	ret = parse((struct cpa_target_raw){ .comm = "x",
					   .startup_window = "604801" }, &s, err);
	EXPECT(ret == -EINVAL, "window above a week");
	ret = parse((struct cpa_target_raw){ .container_pid = "0", .comm = "x" },
		    &s, err);
	EXPECT(ret == -EINVAL, "container pid 0");

	/* accepted combinations the documentation promises */
	ret = parse((struct cpa_target_raw){ .pid = "1,2",
					   .startup_window = "5" }, &s, err);
	EXPECT(ret == 0 && s.mode == CPA_TARGET_DYNAMIC &&
	       s.startup_window_sec == 5, "pid list + window: %s", err);
	ret = parse((struct cpa_target_raw){ .pid = "1", .children = true,
					   .startup_window = "5" }, &s, err);
	EXPECT(ret == 0 && s.children && s.startup_window_sec == 5,
	       "children + window: %s", err);
	ret = parse((struct cpa_target_raw){ .comm = "x", .first_match = true,
					   .children = true }, &s, err);
	EXPECT(ret == 0 && s.first_match && s.children,
	       "first_match + children: %s", err);
	ret = parse((struct cpa_target_raw){ .exe = "/bin/true",
					   .first_match = true }, &s, err);
	EXPECT(ret == 0 && s.first_match && s.new_only && s.n_exes == 1,
	       "exe first_match: %s", err);
	ret = parse((struct cpa_target_raw){ .cgroup = "/a,/b", .comm = "x",
					   .new_only = true }, &s, err);
	EXPECT(ret == 0 && s.n_cgroups == 2 && s.n_comms == 1 && s.new_only &&
	       !s.first_match, "cgroup list + comm new_only: %s", err);
	EXPECT(strstr(s.summary, "new_only") && strstr(s.summary, "cgroup="),
	       "summary %s", s.summary);

	printf("failures=%d\n", failures);
	return failures ? 1 : 0;
}
'''


def test_cpa_target_parse_rules() -> None:
    if shutil.which("gcc") is None:
        pytest.skip("needs gcc")
    with tempfile.TemporaryDirectory(prefix="cpa_target_parse_") as td:
        c_path = Path(td) / "harness.c"
        out_bin = Path(td) / "harness"
        c_path.write_text(HARNESS)
        subprocess.run(
            ["gcc", "-Wall", "-Werror", "-O1", "-I", str(SRC_DIR), "-o",
             str(out_bin), str(c_path), str(SRC_DIR / "cpa_target.c")],
            check=True,
        )
        result = subprocess.run([str(out_bin)], capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "failures=0" in result.stdout, result.stdout
