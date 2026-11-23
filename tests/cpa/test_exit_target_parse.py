# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

"""Unit tests for --exit_comm / --exit_pid / --exit_target_env_* parsing
(cpa_exit_parse in cpa_target.c)."""

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

static int parse(struct cpa_exit_raw raw, struct cpa_exit_spec *spec, char *err)
{
	return cpa_exit_parse(&raw, spec, err, 256);
}

int main(void)
{
	struct cpa_exit_spec s;
	char err[256];
	int ret;

	/* nothing set: exit capture follows the global selection */
	ret = parse((struct cpa_exit_raw){ .comm = "null", .pid = "null" }, &s,
		    err);
	EXPECT(ret == 0 && !cpa_exit_has_targets(&s), "unset");
	ret = parse((struct cpa_exit_raw){ 0 }, &s, err);
	EXPECT(ret == 0 && !cpa_exit_has_targets(&s), "NULL");

	/* names: exact, deduplicated, zero padded */
	ret = parse((struct cpa_exit_raw){ .comm = "python3,server,python3" },
		    &s, err);
	EXPECT(ret == 0 && s.n_comms == 2 && cpa_exit_has_targets(&s),
	       "comms %d %s", s.n_comms, err);
	EXPECT(strcmp(s.comms[0], "python3") == 0 &&
	       strcmp(s.comms[1], "server") == 0, "comm values");
	EXPECT(s.comms[0][7] == 0 && s.comms[0][15] == 0, "padding");
	ret = parse((struct cpa_exit_raw){ .comm = "123456789012345" }, &s, err);
	EXPECT(ret == 0 && s.n_comms == 1, "15 bytes is a full name");

	/* pids */
	ret = parse((struct cpa_exit_raw){ .pid = "12,34,12" }, &s, err);
	EXPECT(ret == 0 && s.n_pids == 2 && s.pids[0] == 12 && s.pids[1] == 34,
	       "pids %d", s.n_pids);

	/* refused */
	ret = parse((struct cpa_exit_raw){ .comm = "a", .pid = "1" }, &s, err);
	EXPECT(ret == -EINVAL && strstr(err, "--exit_pid"), "pid + comm: %s",
	       err);
	ret = parse((struct cpa_exit_raw){ .comm = "a,,b" }, &s, err);
	EXPECT(ret == -EINVAL && strstr(err, "--exit_comm"), "empty: %s", err);
	ret = parse((struct cpa_exit_raw){ .comm = "1234567890123456" }, &s, err);
	EXPECT(ret == -EINVAL && strstr(err, "--exit_comm"), "long: %s", err);
	ret = parse((struct cpa_exit_raw){ .comm = "a,b,c,d,e,f,g,h,i" }, &s,
		    err);
	EXPECT(ret == -EINVAL && strstr(err, "--exit_comm"), "9 names: %s",
	       err);
	ret = parse((struct cpa_exit_raw){ .pid = "0" }, &s, err);
	EXPECT(ret == -EINVAL && strstr(err, "--exit_pid"), "pid 0: %s", err);
	ret = parse((struct cpa_exit_raw){ .pid = "x1" }, &s, err);
	EXPECT(ret == -EINVAL && strstr(err, "--exit_pid"), "pid x1: %s", err);
	ret = parse((struct cpa_exit_raw){
		.pid = "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17" }, &s, err);
	EXPECT(ret == -EINVAL && strstr(err, "--exit_pid"), "17 pids: %s", err);

	/* --exit_target_env_*: names in order, deduplicated */
	ret = parse((struct cpa_exit_raw){ .comm = "a",
		.env_name = "MY_POD_NAME,POD_NAME,MY_POD_NAME",
		.env_values = "job-x,job-y,job-x",
		.env_value_prefix = "msrv-a-" }, &s, err);
	EXPECT(ret == 0 && s.n_env_names == 2 && cpa_exit_has_env_cond(&s) &&
	       strcmp(s.env_names[0], "MY_POD_NAME") == 0 &&
	       strcmp(s.env_names[1], "POD_NAME") == 0, "env names %d %s",
	       s.n_env_names, err);
	EXPECT(s.n_env_values == 2 && strcmp(s.env_values[1], "job-y") == 0 &&
	       s.n_env_prefixes == 1 &&
	       strcmp(s.env_prefixes[0], "msrv-a-") == 0, "env values");
	ret = parse((struct cpa_exit_raw){ .pid = "1", .env_name = "POD_NAME",
		.env_value_prefix = "msrv-" }, &s, err);
	EXPECT(ret == 0 && s.n_env_names == 1 && s.n_env_values == 0,
	       "prefix alone, with pids: %s", err);
	ret = parse((struct cpa_exit_raw){ .comm = "a", .env_name = "POD_NAME",
		.env_values = "job-x" }, &s, err);
	EXPECT(ret == 0 && s.n_env_values == 1 && s.n_env_prefixes == 0,
	       "values alone: %s", err);
	ret = parse((struct cpa_exit_raw){ .comm = "a", .env_name = "null",
		.env_values = "null", .env_value_prefix = "null" }, &s, err);
	EXPECT(ret == 0 && !cpa_exit_has_env_cond(&s), "env unset");
	/* a value may hold '=' */
	ret = parse((struct cpa_exit_raw){ .comm = "a", .env_name = "P",
		.env_values = "a=b" }, &s, err);
	EXPECT(ret == 0 && strcmp(s.env_values[0], "a=b") == 0, "'=': %s", err);

	/* refused: without an own selection */
	ret = parse((struct cpa_exit_raw){ .env_name = "POD_NAME",
		.env_values = "x" }, &s, err);
	EXPECT(ret == -EINVAL &&
	       strstr(err, "--exit_target_env_name requires --exit_comm or "
			   "--exit_pid"), "env alone: %s", err);
	/* a name without a condition, a condition without a name */
	ret = parse((struct cpa_exit_raw){ .comm = "a", .env_name = "POD_NAME" },
		    &s, err);
	EXPECT(ret == -EINVAL && strstr(err, "--exit_target_env_name needs"),
	       "name alone: %s", err);
	ret = parse((struct cpa_exit_raw){ .comm = "a", .env_values = "x" }, &s,
		    err);
	EXPECT(ret == -EINVAL && strstr(err, "need --exit_target_env_name"),
	       "values alone: %s", err);
	ret = parse((struct cpa_exit_raw){ .comm = "a",
		.env_value_prefix = "x" }, &s, err);
	EXPECT(ret == -EINVAL && strstr(err, "need --exit_target_env_name"),
	       "prefix alone: %s", err);
	/* names: empty, too many, too long, '=' */
	ret = parse((struct cpa_exit_raw){ .comm = "a", .env_name = "A,,B",
		.env_values = "x" }, &s, err);
	EXPECT(ret == -EINVAL && strstr(err, "--exit_target_env_name"),
	       "empty env name: %s", err);
	ret = parse((struct cpa_exit_raw){ .comm = "a", .env_name = "A,B,C,D,E",
		.env_values = "x" }, &s, err);
	EXPECT(ret == -EINVAL && strstr(err, "--exit_target_env_name"),
	       "5 env names: %s", err);
	ret = parse((struct cpa_exit_raw){ .comm = "a", .env_name =
		"A123456789012345678901234567890123456789012345678901234567890123",
		.env_values = "x" }, &s, err);
	EXPECT(ret == -EINVAL && strstr(err, "--exit_target_env_name"),
	       "64 byte env name: %s", err);
	ret = parse((struct cpa_exit_raw){ .comm = "a", .env_name = "A=1",
		.env_values = "x" }, &s, err);
	EXPECT(ret == -EINVAL && strstr(err, "--exit_target_env_name"),
	       "env name with '=': %s", err);
	/* values: empty, too many, too long */
	ret = parse((struct cpa_exit_raw){ .comm = "a", .env_name = "P",
		.env_values = "x,,y" }, &s, err);
	EXPECT(ret == -EINVAL && strstr(err, "--exit_target_env_values"),
	       "empty value: %s", err);
	ret = parse((struct cpa_exit_raw){ .comm = "a", .env_name = "P",
		.env_value_prefix = "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17" },
		&s, err);
	EXPECT(ret == -EINVAL && strstr(err, "--exit_target_env_value_prefix"),
	       "17 prefixes: %s", err);
	{
		char longv[CPA_EXIT_ENV_VALUE_LEN + 1];

		memset(longv, 'v', CPA_EXIT_ENV_VALUE_LEN);
		longv[CPA_EXIT_ENV_VALUE_LEN] = '\0';
		ret = parse((struct cpa_exit_raw){ .comm = "a", .env_name = "P",
			.env_values = longv }, &s, err);
		EXPECT(ret == -EINVAL && strstr(err, "--exit_target_env_values"),
		       "256 byte value: %s", err);
		longv[CPA_EXIT_ENV_VALUE_LEN - 1] = '\0';
		ret = parse((struct cpa_exit_raw){ .comm = "a", .env_name = "P",
			.env_values = longv }, &s, err);
		EXPECT(ret == 0, "255 byte value: %s", err);
	}

	printf("failures=%d\n", failures);
	return failures ? 1 : 0;
}
'''


def test_cpa_exit_target_parse() -> None:
    if shutil.which("gcc") is None:
        pytest.skip("needs gcc")
    with tempfile.TemporaryDirectory(prefix="cpa_exit_parse_") as td:
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
