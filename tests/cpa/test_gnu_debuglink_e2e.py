# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

"""End-to-end symbolization of a stripped ELF via .gnu_debuglink.

Reproduces a strip-only deployment layout: the running executable keeps
just .dynsym and carries .gnu_debuglink pointing at a separate debuginfo
file under an adjacent .debug/ directory. The unwinder must find that
file, verify its CRC32, and resolve static LOCAL functions absent from
.dynsym.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time

import pytest

from .cpa_utils import get_first_cpa_records_from_test_dir, run_cpa_monitor


WORKLOAD_NAME = "dbgl_wl"
ANCHOR_SYMBOLS = ("dbgl_anchor_leaf", "dbgl_anchor_poll", "dbgl_anchor_run")
UNRESOLVED_FRAME_RE = re.compile(r"^0x[0-9a-fA-F]+ \[" + WORKLOAD_NAME + r"\]$")

WORKLOAD_C = r"""
#include <stdlib.h>
#include <stdio.h>

__attribute__((noinline)) static long dbgl_anchor_leaf(long x)
{
    for (volatile long i = 0; i < 1000; i++)
        x += i * 3;
    return x;
}

__attribute__((noinline)) static long dbgl_anchor_poll(long x)
{
    return dbgl_anchor_leaf(x) + dbgl_anchor_leaf(x + 1);
}

__attribute__((noinline)) static long dbgl_anchor_run(long seconds)
{
    long acc = 0;
    long deadline = seconds * 1000000UL;
    for (long i = 0; i < deadline; i++)
        acc += dbgl_anchor_poll(i);
    return acc;
}

int main(int argc, char **argv)
{
    long seconds = argc > 1 ? strtol(argv[1], NULL, 10) : 60;
    long acc = dbgl_anchor_run(seconds);
    if (acc == 123456789)
        printf("%ld\n", acc);
    return 0;
}
"""


def _require_toolchain():
    tools = {name: shutil.which(name) for name in ("gcc", "objcopy", "strip")}
    missing = [name for name, path in tools.items() if path is None]
    if missing:
        pytest.skip(f"missing binutils toolchain: {' '.join(missing)}")
    return tools


def _build_stripped_debuglink_workload(tools, root_dir):
    libexec = root_dir / "libexec"
    debug_dir = libexec / ".debug"
    debug_dir.mkdir(parents=True)

    src = root_dir / "dbgl_wl.c"
    src.write_text(WORKLOAD_C)

    full_bin = root_dir / "dbgl_wl.full"
    main_bin = libexec / WORKLOAD_NAME
    debug_file = debug_dir / f"{WORKLOAD_NAME}.debug"

    subprocess.run([tools["gcc"], "-O2", "-g", str(src), "-o", str(full_bin)],
                   check=True, capture_output=True)
    subprocess.run([tools["objcopy"], "--only-keep-debug", str(full_bin),
                    str(debug_file)], check=True, capture_output=True)
    subprocess.run([tools["strip"], "--strip-all", str(full_bin)],
                   check=True, capture_output=True)
    shutil.move(str(full_bin), str(main_bin))
    subprocess.run(
        [
            tools["objcopy"],
            f"--add-gnu-debuglink=.debug/{WORKLOAD_NAME}.debug",
            str(main_bin),
        ],
        check=True,
        capture_output=True,
        cwd=str(libexec),
    )
    return main_bin


def test_cpa_resolves_stripped_elf_via_gnu_debuglink(cpa_backend, tmp_path):
    if os.geteuid() != 0:
        pytest.skip("cpa monitor needs root to attach BPF/perf events")

    tools = _require_toolchain()
    main_bin = _build_stripped_debuglink_workload(tools, tmp_path)

    workload = subprocess.Popen(
        [str(main_bin), "60"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(1)
        if workload.poll() is not None:
            pytest.fail("debuglink workload exited before sampling started")

        extra = ["--freq", "99", "--duration", "8", "--pid", str(workload.pid)]
        if cpa_backend == "perf":
            extra = ["--freq", "99", "--duration", "8", "--backend", "perf"]

        try:
            run_cpa_monitor(str(tmp_path), run_time=8, extra_args=extra)
        except AssertionError as exc:
            output = str(exc)
            if ("Operation not permitted" in output
                    or "Permission denied" in output
                    or "RLIMIT_MEMLOCK" in output):
                pytest.skip("cpa monitor cannot attach BPF/perf here")
            raise

        records = get_first_cpa_records_from_test_dir(str(tmp_path))
        assert records, "no cpa records captured"

        target_records = [r for r in records if r.process_name == WORKLOAD_NAME]
        assert target_records, f"no {WORKLOAD_NAME} records in capture"

        named_samples = 0
        unresolved_frames = []
        for record in target_records:
            for frame in record.stack or []:
                if UNRESOLVED_FRAME_RE.match(frame):
                    unresolved_frames.append(frame)
            if any(frame.split("+", 1)[0] in ANCHOR_SYMBOLS
                   for frame in record.stack or []):
                named_samples += record.samples

        assert named_samples > 0, (
            "LOCAL functions from the .gnu_debuglink debuginfo were not "
            "resolved; expected one of: " + ", ".join(ANCHOR_SYMBOLS)
        )
        assert not unresolved_frames, (
            "stripped ELF frames stayed unresolved despite gnu_debuglink: "
            f"{unresolved_frames[:5]}"
        )
    finally:
        workload.terminate()
        try:
            workload.wait(timeout=5)
        except subprocess.TimeoutExpired:
            workload.kill()
