# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance


import logging
import os
import signal
import subprocess
import sys
import time
from typing import Generator, List, Optional

import pytest

from .cpa_utils import (
    get_first_cpa_records_from_test_dir,
    parse_cpa_prof_file,
    run_cpa_monitor,
)
from .resource.run_workloads import run_workloads, terminate_workloads

pytestmark = [pytest.mark.usefixtures("print_test_name")]


@pytest.fixture
def workload_by_c_example() -> Generator[int, None, None]:
    manager = run_workloads(["offcpu_sym_c"])
    try:
        time.sleep(1)
        assert manager.processes, "offcpu_sym_c did not start properly."
        pid = manager.processes[0].pid
        assert pid and pid > 0, "Invalid PID for offcpu_sym_c."
        yield int(pid)
    finally:
        terminate_workloads(manager)


def run_and_verify_offcpu_probe(
    cpa_output_dir: str,
    mode: str,
    oneshot: bool,
    expected_min_samples: int,
    expected_max_samples: int,
    required_symbols: List[str],
    workload_pid: int,
    pytestconfig: Optional[pytest.Config] = None,
):
    """Run one offcpu/probe mode and verify the exported stacks."""
    monitor_run_time_seconds = 10

    extra_args = ["--pid", str(workload_pid)]
    if mode == "offcpu":
        extra_args.append("--offcpu")
    elif mode == "probe":
        extra_args.extend(["--probe", "kprobe:hrtimer_nanosleep"])

    output_file = os.path.join(cpa_output_dir, "cpa_off.prof")

    if oneshot:
        extra_args.extend(["--oneshot", "--output_prof", output_file])
        run_cpa_monitor(cpa_output_dir, run_time=monitor_run_time_seconds, extra_args=extra_args)
        records = parse_cpa_prof_file(output_file)
    else:
        run_cpa_monitor(
            cpa_output_dir,
            run_time=monitor_run_time_seconds,
            extra_args=extra_args + ["--duration", str(monitor_run_time_seconds)],
        )
        records = get_first_cpa_records_from_test_dir(cpa_output_dir, pytestconfig)

    assert records, f"No CPA records found for {mode} {'oneshot' if oneshot else 'normal'} mode."

    total_samples = sum(record.samples for record in records)
    logging.info(f"Total samples for {mode} {'oneshot' if oneshot else 'normal'} mode: {total_samples}")
    assert expected_min_samples <= total_samples <= expected_max_samples, (
        f"Sample count for {mode} {'oneshot' if oneshot else 'normal'} mode ({total_samples}) "
        f"is outside the expected range [{expected_min_samples}, {expected_max_samples}]."
    )

    found_symbols = {symbol: False for symbol in required_symbols}
    for record in records:
        for stack_frame in record.stack:
            for symbol in required_symbols:
                if symbol in stack_frame:
                    found_symbols[symbol] = True

    for symbol, found in found_symbols.items():
        assert found, f"Symbol '{symbol}' not found in stack traces."

    logging.info(f"Test for {mode} {'oneshot' if oneshot else 'normal'} mode passed.")


@pytest.mark.parametrize(
    "mode, oneshot, expected_min_samples, expected_max_samples, required_symbols",
    [
        ("offcpu", False, 8 * 10**9, 11 * 10**9, ["offcpu_stage_5", "hrtimer_nanosleep"]),
        ("offcpu", True, 8 * 10**9, 11 * 10**9, ["offcpu_stage_5", "hrtimer_nanosleep"]),
        ("probe", False, 35, 60, ["offcpu_stage_5", "hrtimer_nanosleep"]),
        ("probe", True, 35, 60, ["offcpu_stage_5", "hrtimer_nanosleep"]),
    ],
)
def test_cpa_offcpu_and_probe(
    mode,
    oneshot,
    expected_min_samples,
    expected_max_samples,
    required_symbols,
    workload_by_c_example,
    tmp_path,
    pytestconfig,
):
    run_and_verify_offcpu_probe(
        mode=mode,
        oneshot=oneshot,
        expected_min_samples=expected_min_samples,
        expected_max_samples=expected_max_samples,
        required_symbols=required_symbols,
        workload_pid=workload_by_c_example,
        cpa_output_dir=str(tmp_path),
        pytestconfig=pytestconfig,
    )


def test_cpa_offcpu_keeps_tgid_in_metadata_for_multithread_process(tmp_path, pytestconfig):
    script_path = tmp_path / "offcpu_threads.py"
    script_path.write_text(
        (
            "import threading\n"
            "import time\n"
            "\n"
            "def sleeper():\n"
            "    while True:\n"
            "        time.sleep(0.2)\n"
            "\n"
            "for _ in range(3):\n"
            "    t = threading.Thread(target=sleeper, daemon=True)\n"
            "    t.start()\n"
            "\n"
            "while True:\n"
            "    time.sleep(0.2)\n"
        ),
        encoding="utf-8",
    )

    proc = subprocess.Popen([sys.executable, str(script_path)])

    try:
        time.sleep(1)
        run_cpa_monitor(
            str(tmp_path),
            run_time=8,
            extra_args=[
                "--offcpu",
                "--pid",
                str(proc.pid),
                "--duration",
                "8",
            ],
        )

        records = get_first_cpa_records_from_test_dir(str(tmp_path), pytestconfig)
        assert records, "No records exported for multithread offcpu test."

        thread_records = [
            record
            for record in records
            if record.process_name.startswith("python") and record.pid != proc.pid
        ]
        assert thread_records, "No offcpu worker-thread records were captured."
        assert any(record.cgroup_id == proc.pid for record in thread_records)
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
