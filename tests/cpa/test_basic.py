# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance


import subprocess

import pytest

from .conftest import run_command


def _write_invalid_btf(tmp_path):
    bad_btf = tmp_path / "invalid.btf"
    bad_btf.write_text("not-a-btf-file\n", encoding="utf-8")
    return bad_btf


def test_cpa_exits_when_no_args() -> None:
    p = subprocess.run(
        ["./build/bin/cpa"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=3,
    )
    assert p.returncode != 0
    assert "usage" in (p.stdout + p.stderr).lower()


def test_cpa_monitor_startup_failure_is_reported(tmp_path):
    stdout, stderr, return_code = run_command(
        [
            "monitor",
            "--backend=perf",
            "--freq=1",
            "--duration=1",
            "--store_dir",
            str(tmp_path),
        ]
    )

    full_output = f"{stdout}{stderr}"
    assert return_code != 0
    assert "Failed to init worker perf_capture_worker" in full_output
    assert "Failed to join timer_thread, thread not created" not in full_output


def test_cpa_monitor_bench_reports_dwarf_unwind_stats(tmp_path):
    stdout, stderr, return_code = run_command(
        [
            "monitor",
            "--backend=perf",
            "--freq=49",
            "--duration=2",
            "--store_dir",
            str(tmp_path),
            "--bench",
            "--log_print_cycles=1",
        ],
        timeout=20,
    )

    full_output = f"{stdout}{stderr}"
    assert return_code == 0, full_output
    assert "Bench DWARF Unwind:" in full_output
    assert "rate=" in full_output
    assert "avg=" in full_output
    assert "min=" in full_output
    assert "max=" in full_output
    assert "Bench DWARF Histogram:" in full_output


def test_cpa_monitor_rejects_perf_backend_with_offcpu(tmp_path):
    stdout, stderr, return_code = run_command(
        [
            "monitor",
            "--backend=perf",
            "--offcpu",
            "--duration=1",
            "--store_dir",
            str(tmp_path),
        ]
    )

    full_output = f"{stdout}{stderr}".lower()
    assert return_code != 0
    assert "perf backend only supports on-cpu continuous profiling" in full_output
    assert "require bpf backend" in full_output


def test_cpa_monitor_rejects_perf_backend_with_probe(tmp_path):
    stdout, stderr, return_code = run_command(
        [
            "monitor",
            "--backend=perf",
            "--probe=kprobe:try_to_free_pages",
            "--duration=1",
            "--store_dir",
            str(tmp_path),
        ]
    )

    full_output = f"{stdout}{stderr}".lower()
    assert return_code != 0
    assert "perf backend only supports on-cpu continuous profiling" in full_output
    assert "require bpf backend" in full_output


def test_cpa_monitor_falls_back_to_perf_when_bpf_prereqs_missing(tmp_path):
    invalid_btf = _write_invalid_btf(tmp_path)

    stdout, stderr, return_code = run_command(
        [
            "monitor",
            "--backend=bpf",
            "--freq=49",
            "--duration=1",
            "--store_dir",
            str(tmp_path),
            f"--btf_path={invalid_btf}",
        ]
    )

    full_output = f"{stdout}{stderr}".lower()
    assert return_code == 0
    assert "warning" in full_output
    assert "falling back to perf" in full_output
    assert "irqoff" in full_output


def test_cpa_monitor_rejects_bpf_only_offcpu_when_bpf_prereqs_missing(tmp_path):
    invalid_btf = _write_invalid_btf(tmp_path)

    stdout, stderr, return_code = run_command(
        [
            "monitor",
            "--backend=bpf",
            "--offcpu",
            "--duration=1",
            "--store_dir",
            str(tmp_path),
            f"--btf_path={invalid_btf}",
        ]
    )

    full_output = f"{stdout}{stderr}".lower()
    assert return_code != 0
    assert "requires bpf backend" in full_output
    assert "cannot fall back to perf" in full_output


@pytest.mark.parametrize(
    "extra_args",
    [
        ["--kernel_stack"],
        ["--oneshot", "--output_prof", "cpa.prof"],
    ],
)
def test_cpa_monitor_rejects_other_bpf_only_modes_when_bpf_prereqs_missing(tmp_path, extra_args):
    invalid_btf = _write_invalid_btf(tmp_path)

    stdout, stderr, return_code = run_command(
        [
            "monitor",
            "--backend=bpf",
            "--duration=1",
            "--store_dir",
            str(tmp_path),
            f"--btf_path={invalid_btf}",
            *extra_args,
        ]
    )

    full_output = f"{stdout}{stderr}".lower()
    assert return_code != 0
    assert "requires bpf backend" in full_output
    assert "cannot fall back to perf" in full_output


def test_cpa_monitor_accepts_null_btf_path_as_default_btf(tmp_path):
    stdout, stderr, return_code = run_command(
        [
            "monitor",
            "--backend=bpf",
            "--freq=49",
            "--duration=1",
            "--store_dir",
            str(tmp_path),
            "--btf_path=null",
        ]
    )

    full_output = f"{stdout}{stderr}".lower()
    assert return_code == 0
    assert "custom btf path null is not readable" not in full_output


def test_cpa_monitor_rejects_invalid_backend_value(tmp_path):
    stdout, stderr, return_code = run_command(
        [
            "monitor",
            "--backend=bogus",
            "--duration=1",
            "--store_dir",
            str(tmp_path),
        ]
    )

    full_output = f"{stdout}{stderr}".lower()
    assert return_code != 0
    assert "backend" in full_output
    assert "bpf or perf" in full_output


def test_cpa_monitor_rejects_non_positive_persistent_day(tmp_path):
    stdout, stderr, return_code = run_command(
        [
            "monitor",
            "--backend=perf",
            "--persistent_day=0",
            "--duration=1",
            "--store_dir",
            str(tmp_path),
        ]
    )

    full_output = f"{stdout}{stderr}".lower()
    assert return_code != 0
    assert "persistent_day" in full_output
    assert ("> 0" in full_output) or ("greater than 0" in full_output)


def test_cpa_monitor_rejects_perf_backend_with_oneshot(tmp_path):
    stdout, stderr, return_code = run_command(
        [
            "monitor",
            "--backend=perf",
            "--oneshot",
            "--duration=1",
            "--output_prof",
            str(tmp_path / "cpa.prof"),
        ]
    )

    full_output = f"{stdout}{stderr}".lower()
    assert return_code != 0
    assert "perf backend only supports on-cpu continuous profiling" in full_output


@pytest.mark.parametrize(
    "extra_args",
    [
        ["--pid=123"],
        ["--comm=test-proc"],
        ["--kernel_stack"],
        ["--stack_size=16384"],
    ],
)
def test_cpa_monitor_rejects_perf_backend_with_bpf_side_options(tmp_path, extra_args):
    stdout, stderr, return_code = run_command(
        [
            "monitor",
            "--backend=perf",
            "--duration=1",
            "--store_dir",
            str(tmp_path),
            *extra_args,
        ]
    )

    full_output = f"{stdout}{stderr}".lower()
    assert return_code != 0
    assert "require bpf backend" in full_output
