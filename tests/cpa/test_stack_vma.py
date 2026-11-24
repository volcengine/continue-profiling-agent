# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

"""User stack copy bounded by the VMA holding SP (bpf_find_vma).

Where the kernel offers bpf_find_vma (5.17, and vendor kernels that
backported it) the on-CPU ring-buffer capture object copies the user stack up
to the end of the VMA holding SP and never past it: a page inside it that
cannot be read is zero-filled and the copy goes on, a stack in an I/O or PFN
mapping is not read at all.  Without the helper, with another object, or with
CPA_DISABLE_STACK_VMA_BOUND=1 the copy stops at the first unreadable page.
Off-CPU capture keeps that copy: the bound would add a bpf_find_vma (an mmap
lock trylock) to every context switch.

Workload: stack_vma/big_frame_app.c.  Its leaves run under a ~48 KiB frame
whose middle pages were never faulted in (CPython's select_select_impl has the
same shape), and a third thread parks its SP in [vvar], a VM_PFNMAP mapping.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from .conftest import run_command
from .cpa_utils import get_first_cpa_records_from_test_dir, run_cpa_monitor

HERE = Path(__file__).resolve().parent
DURATION = 12  # 4.14 takes seconds to start: sample well past it
CHAIN = ["start_thread", "vma_spin_thread", "vma_big_frame", "vma_spin_leaf"]


@pytest.fixture(scope="module")
def big_frame_app(tmp_path_factory) -> Path:
    if os.geteuid() != 0:
        pytest.skip("cpa monitor needs root")
    cc = shutil.which("gcc")
    if not cc:
        pytest.skip("gcc is required to build the workload")
    app = tmp_path_factory.mktemp("stack_vma") / "big_frame_app"
    # stack clash protection would probe, and so fault in, every frame page
    subprocess.run([cc, "-O1", "-g", "-fno-omit-frame-pointer", "-fno-stack-clash-protection",
                    "-fno-stack-protector", "-pthread", "-Wall", "-Werror", "-o", str(app),
                    str(HERE / "stack_vma/big_frame_app.c")], check=True, timeout=120)
    return app


@pytest.fixture(scope="module")
def find_vma_supported() -> bool:
    stdout, stderr, rc = run_command(["capabilities"])
    assert rc == 0, stdout + stderr
    return "capability.find_vma.state: supported" in stdout


def _profile(app: Path, store: Path, monkeypatch, bounded: bool):
    if bounded:
        monkeypatch.delenv("CPA_DISABLE_STACK_VMA_BOUND", raising=False)
    else:
        monkeypatch.setenv("CPA_DISABLE_STACK_VMA_BOUND", "1")
    workload = subprocess.Popen([str(app), str(DURATION + 30)], stdout=subprocess.PIPE, text=True)
    try:
        ready = workload.stdout.readline()
        assert ready.startswith("ready"), ready
        stdout, stderr = run_cpa_monitor(str(store), run_time=DURATION,
                                         extra_args=["--pid", str(workload.pid), "--duration", str(DURATION),
                                                     "--freq", "99", "--stack_size", "57344"])
        output = stdout.decode(errors="ignore") + stderr.decode(errors="ignore")
        return output, get_first_cpa_records_from_test_dir(str(store))
    finally:
        workload.kill()
        workload.wait()


def _chain_samples(records):
    """(samples of the leaf, of those the ones carrying the whole chain)"""
    leaf, whole = 0, 0
    for record in records:
        if CHAIN[-1] not in record.stack:
            continue
        leaf += record.samples
        i = record.stack.index(CHAIN[-1])
        if record.stack[max(0, i - len(CHAIN) + 1):i + 1] == CHAIN:
            whole += record.samples
    return leaf, whole


def test_big_frame_stack_is_whole_within_its_vma(big_frame_app, find_vma_supported, tmp_path, monkeypatch):
    if not find_vma_supported:
        pytest.skip("the kernel has no bpf_find_vma: the copy stays unbounded")
    output, records = _profile(big_frame_app, tmp_path, monkeypatch, bounded=True)
    assert "user_stack_copy=vma_bound" in output, output[-3000:]
    leaf, whole = _chain_samples(records)
    assert leaf >= 100, (leaf, whole)
    # find_vma may find the mmap lock busy: those samples take the old copy
    assert whole >= 0.9 * leaf, (leaf, whole)


def test_without_the_bound_the_copy_stops_at_the_first_hole(big_frame_app, tmp_path, monkeypatch):
    """The fallback copy, kept as it was: the first never-faulted page of the
    big frame ends it and vma_big_frame is lost."""
    output, records = _profile(big_frame_app, tmp_path, monkeypatch, bounded=False)
    assert "user_stack_copy=unbounded" in output, output[-3000:]
    leaf, whole = _chain_samples(records)
    assert leaf >= 100, (leaf, whole)
    assert whole <= 0.1 * leaf, (leaf, whole)
