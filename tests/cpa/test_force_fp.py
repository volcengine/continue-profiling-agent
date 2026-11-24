# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

"""cpa monitor --force_fp: user stacks by frame pointers only.

A program built with frame pointers is profiled with and without the option:
with it every user stack is a frame-pointer unwind (the stats count no DWARF
one) and still carries its whole chain; without it the DWARF path runs.  On
a kernel without bpf_get_stack the option is ignored, saying so.
"""

import os
import re
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

from .conftest import run_command
from .cpa_utils import get_first_cpa_records_from_test_dir, run_cpa_monitor

APP = r"""
#include <stdio.h>
#include <unistd.h>

volatile unsigned long sink;

/* a function that returns, with a frame of its own */
__attribute__((noinline)) unsigned long fp_leaf(unsigned long n)
{
	for (unsigned long i = 0; i < n; i++)
		sink += i;
	return sink;
}

__attribute__((noinline)) void fp_mid(void)
{
	for (;;)
		fp_leaf(1000000);
}

int main(void)
{
	printf("ready\n");
	fflush(stdout);
	fp_mid();
	return 0;
}
"""
CHAIN = ["main", "fp_mid", "fp_leaf"]
DURATION = 12


@pytest.fixture(scope="module")
def fp_app(tmp_path_factory) -> Path:
    if os.geteuid() != 0:
        pytest.skip("cpa monitor needs root")
    cc = shutil.which("gcc")
    if not cc:
        pytest.skip("gcc is required to build the workload")
    d = tmp_path_factory.mktemp("force_fp")
    (d / "fp_app.c").write_text(textwrap.dedent(APP))
    # -O0 and a leaf frame pointer: every function sets up its frame record
    # (compilers drop a leaf's even with -fno-omit-frame-pointer, and on
    # arm64 a leaf without one hides its caller from the frame-pointer chain)
    subprocess.run([cc, "-O0", "-g", "-fno-omit-frame-pointer", "-mno-omit-leaf-frame-pointer",
                    "-o", str(d / "fp_app"), str(d / "fp_app.c")], check=True, timeout=120)
    return d / "fp_app"


def _get_stack_supported() -> bool:
    stdout, stderr, rc = run_command(["capabilities"])
    assert rc == 0, stdout + stderr
    return "capability.get_stack_perf_event.state: supported" in stdout


def _profile(app: Path, store: Path, extra):
    workload = subprocess.Popen([str(app)], stdout=subprocess.PIPE, text=True)
    try:
        assert workload.stdout.readline().startswith("ready")
        stdout, stderr = run_cpa_monitor(str(store), run_time=DURATION,
                                         extra_args=["--pid", str(workload.pid), "--duration", str(DURATION),
                                                     "--freq", "99", "--log_print_cycles=1", *extra])
        return stdout.decode(errors="ignore") + stderr.decode(errors="ignore"), \
            get_first_cpa_records_from_test_dir(str(store))
    finally:
        workload.kill()
        workload.wait()


def _counts(output):
    found = re.findall(r"\[FP\] (\d+) \[DWARF\] (\d+)", output)
    assert found, output[-3000:]
    return tuple(int(x) for x in found[-1])


def _whole(records):
    leaf, whole = 0, 0
    for r in records:
        if "fp_leaf" in r.stack:
            leaf += r.samples
            i = r.stack.index("fp_leaf")
            if r.stack[max(0, i - 2):i + 1] == CHAIN:
                whole += r.samples
    return leaf, whole


def test_force_fp_unwinds_by_frame_pointers_only(fp_app, tmp_path):
    output, records = _profile(fp_app, tmp_path, ["--force_fp"])
    fp, dwarf = _counts(output)
    if not _get_stack_supported():
        assert "--force_fp ignored: this kernel has no bpf_get_stack" in output, output[-3000:]
        assert dwarf > 0, (fp, dwarf)
        return
    assert fp > 0 and dwarf == 0, (fp, dwarf)
    leaf, whole = _whole(records)
    assert leaf >= 100 and whole >= 0.9 * leaf, (leaf, whole)


def test_without_force_fp_dwarf_runs(fp_app, tmp_path):
    output, records = _profile(fp_app, tmp_path, [])
    fp, dwarf = _counts(output)
    assert dwarf > 0, (fp, dwarf)
    assert "--force_fp ignored" not in output
    leaf, whole = _whole(records)
    assert leaf >= 100 and whole >= 0.9 * leaf, (leaf, whole)
