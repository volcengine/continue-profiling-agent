# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

import os
import subprocess

import pytest

from .conftest import CLI_BINARY, is_asan_build, print_test_name, run_command
from .cpa_utils import DEFAULT_MONITOR_ARGS, get_first_cpa_records_from_test_dir
from .resource.run_workloads import run_workloads, terminate_workloads

pytestmark = [pytest.mark.usefixtures("print_test_name")]


def _run_asan_monitor(store_dir: str, backend: str) -> None:
    current_args = DEFAULT_MONITOR_ARGS.copy()
    current_args["--duration"] = "4"
    if backend == "perf":
        current_args["--backend"] = "perf"
        current_args.pop("--stack_size", None)

    command = [CLI_BINARY, "monitor", "--store_dir", store_dir]
    for key, value in current_args.items():
        if not value:
            command.append(key)
            continue
        command.append(f"{key}={value}")

    proc = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout, stderr = proc.communicate(timeout=60)
    full_output = f"{stdout}{stderr}"
    assert proc.returncode == 0, full_output
    assert "AddressSanitizer" not in full_output
    assert "ERROR: LeakSanitizer" not in full_output


@pytest.mark.skipif(not is_asan_build(), reason="requires an ASan-built cpa binary")
@pytest.mark.parametrize("backend", ["default", "perf"])
def test_cpa_asan_monitor_show_e2e(tmp_path, monkeypatch, backend):
    workload_manager = None

    try:
        workload_manager = run_workloads(["sym_c"])
        monkeypatch.setenv("ASAN_OPTIONS", "detect_leaks=0:abort_on_error=1")

        _run_asan_monitor(str(tmp_path), backend)

        records = get_first_cpa_records_from_test_dir(str(tmp_path))
        assert records, "No records exported from ASan monitor run."

        store_dirs = sorted(
            entry
            for entry in os.listdir(tmp_path)
            if os.path.isdir(os.path.join(tmp_path, entry)) and entry.startswith("cpa_")
        )
        assert store_dirs, f"No CPA store directory found under {tmp_path}."

        store_dir = os.path.join(tmp_path, store_dirs[0])
        output_prof = os.path.join(tmp_path, f"asan-{backend}.prof")
        stdout, stderr, return_code = run_command(
            [
                "show",
                "--read",
                store_dir,
                "--output_num",
                "1",
                "--output_prof",
                output_prof,
            ]
        )

        full_output = f"{stdout}{stderr}"
        assert return_code == 0, full_output
        assert os.path.exists(output_prof), f"Expected flamegraph profile at {output_prof}."
        assert "AddressSanitizer" not in full_output
        assert "ERROR: LeakSanitizer" not in full_output
    finally:
        if workload_manager:
            terminate_workloads(workload_manager)
