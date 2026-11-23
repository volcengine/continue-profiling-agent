# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

"""Unit test of --exit_target_env_*'s store (src/cpa_monitor/cpa_exit_env.c).

The harness links the real cpa_exit_env.c and reads the environ of real child
processes: exact and prefix matches, the first listed name that is set, none
set, a gone process, per-instance keys, reaping, and the reader thread.  The
re-read of a live process whose environ is not there yet (4.14's exec
fallback) is covered end to end by exit_capture/run_exit_e2e.py case 10.
"""

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MON_DIR = REPO_ROOT / "src/cpa_monitor"

HARNESS = r'''
#include "cpa_exit_env.h"

#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int failures;

#define EXPECT(cond, ...) do { \
	if (!(cond)) { \
		failures++; \
		printf("FAIL %s:%d: ", __FILE__, __LINE__); \
		printf(__VA_ARGS__); \
		printf("\n"); \
	} \
} while (0)

void cli_raw_output(int level, bool end, const char *format, ...)
{
	va_list ap;

	(void)level;
	(void)end;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	fputc('\n', stderr);
}

/* a sleeping child with exactly @env */
static pid_t child(char *const env[])
{
	pid_t pid = fork();

	if (pid == 0) {
		char *argv[] = { "sleep", "30", NULL };

		execve("/bin/sleep", argv, env);
		_exit(127);
	}
	usleep(100 * 1000);	/* past exec: the new environ is in place */
	return pid;
}

static void reap(pid_t pid)
{
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
}

static enum cpa_exit_env_verdict wait_verdict(uint32_t pid, uint64_t id)
{
	for (int i = 0; i < 200; i++) {
		enum cpa_exit_env_verdict v = cpa_exit_env_verdict(pid, id);

		if (v != CPA_EXIT_ENV_UNKNOWN)
			return v;
		usleep(10 * 1000);
	}
	return CPA_EXIT_ENV_UNKNOWN;
}

int main(void)
{
	struct cpa_exit_spec spec = { 0 };
	char *names[] = { "MY_POD_NAME", "POD_NAME" };
	char *value;

	spec.n_comms = 1;
	strcpy(spec.env_names[0], "MY_POD_NAME");
	strcpy(spec.env_names[1], "POD_NAME");
	spec.n_env_names = 2;
	strcpy(spec.env_values[0], "job-x");
	spec.n_env_values = 1;
	strcpy(spec.env_prefixes[0], "msrv-a-");
	spec.n_env_prefixes = 1;
	cpa_exit_env_configure(&spec);
	EXPECT(cpa_exit_env_enabled(), "enabled");
	EXPECT(cpa_exit_env_value_matches("job-x"), "exact");
	EXPECT(!cpa_exit_env_value_matches("job-xy"), "exact is exact");
	EXPECT(cpa_exit_env_value_matches("msrv-a-1"), "prefix");
	EXPECT(!cpa_exit_env_value_matches("msrv-b-1"), "other prefix");

	/* the first listed name set to a non-empty value wins */
	char *e1[] = { "POD_NAME=msrv-a-1", "MY_POD_NAME=", NULL };
	pid_t p1 = child(e1);
	EXPECT(cpa_exit_env_lookup(p1, names, 2, &value) == 0 && value &&
	       strcmp(value, "msrv-a-1") == 0, "empty MY_POD_NAME skipped: %s", value);
	free(value);
	char *e2[] = { "POD_NAME=msrv-a-2", "MY_POD_NAME=other-1", NULL };
	pid_t p2 = child(e2);
	EXPECT(cpa_exit_env_lookup(p2, names, 2, &value) == 0 && value &&
	       strcmp(value, "other-1") == 0, "MY_POD_NAME first: %s", value);
	free(value);
	char *e3[] = { "APP=1", NULL };
	pid_t p3 = child(e3);
	EXPECT(cpa_exit_env_lookup(p3, names, 2, &value) == 0 && !value, "none set");
	char *e4[] = { "MY_POD_NAME=job-x", NULL };
	pid_t p4 = child(e4);

	/* verdicts, per instance */
	EXPECT(cpa_exit_env_read(p1, 11), "read p1");
	EXPECT(cpa_exit_env_read(p2, 22), "read p2");
	EXPECT(cpa_exit_env_read(p3, 33), "read p3");
	EXPECT(cpa_exit_env_verdict(p1, 11) == CPA_EXIT_ENV_MATCH, "p1 match");
	EXPECT(cpa_exit_env_verdict(p2, 22) == CPA_EXIT_ENV_MISMATCH, "p2 mismatch");
	EXPECT(cpa_exit_env_verdict(p3, 33) == CPA_EXIT_ENV_MISMATCH, "p3 none set");
	EXPECT(cpa_exit_env_verdict(p1, 12) == CPA_EXIT_ENV_UNKNOWN, "other instance");
	EXPECT(cpa_exit_env_count() == 3, "count %u", cpa_exit_env_count());

	/* a gone process has no environ: no verdict */
	reap(p3);
	EXPECT(!cpa_exit_env_read(p3, 34), "gone: nothing read");
	EXPECT(cpa_exit_env_verdict(p3, 34) == CPA_EXIT_ENV_UNKNOWN, "gone: unknown");

	/* reaping drops only its own instance */
	cpa_exit_env_on_pid_exit(p1, 12);
	EXPECT(cpa_exit_env_verdict(p1, 11) == CPA_EXIT_ENV_MATCH, "other instance kept");
	cpa_exit_env_on_pid_exit(p1, 11);
	EXPECT(cpa_exit_env_verdict(p1, 11) == CPA_EXIT_ENV_UNKNOWN, "reaped");

	/* the reader thread reads what is selected */
	EXPECT(cpa_exit_env_start() == 0, "reader start");
	cpa_exit_env_selected(p4, 44);
	EXPECT(wait_verdict(p4, 44) == CPA_EXIT_ENV_MATCH, "reader: exact job-x");
	cpa_exit_env_stop();
	EXPECT(cpa_exit_env_count() == 0, "stop clears the store");

	reap(p1);
	reap(p2);
	reap(p4);
	printf("failures=%d\n", failures);
	return failures ? 1 : 0;
}
'''


@pytest.mark.parametrize("sanitize", ["", "address,undefined", "thread"])
def test_cpa_exit_env_store(tmp_path: Path, sanitize: str) -> None:
    if shutil.which("gcc") is None:
        pytest.skip("needs gcc")
    c_path = tmp_path / "harness.c"
    out_bin = tmp_path / "harness"
    c_path.write_text(HARNESS)
    cmd = ["gcc", "-Wall", "-Werror", "-O1", "-g", "-pthread",
           "-I", str(MON_DIR), "-I", str(REPO_ROOT / "src"),
           "-I", str(REPO_ROOT / "src/cli_struct_helper")]
    if sanitize:
        cmd += [f"-fsanitize={sanitize}"]
    cmd += ["-o", str(out_bin), str(c_path), str(MON_DIR / "cpa_exit_env.c")]
    build = subprocess.run(cmd, capture_output=True, text=True)
    if sanitize and build.returncode != 0 and "sanitize" in build.stderr:
        pytest.skip("compiler without this sanitizer")
    assert build.returncode == 0, build.stderr
    result = subprocess.run([str(out_bin)], capture_output=True, text=True, timeout=120,
                            env={"TSAN_OPTIONS": "halt_on_error=1"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "failures=0" in result.stdout, result.stdout
