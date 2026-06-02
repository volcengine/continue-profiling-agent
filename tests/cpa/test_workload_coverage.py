# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

import logging
import os
import platform
import re
import signal
import subprocess
import time
from typing import List

import pytest

from .conftest import CLI_BINARY, cpa_backend, is_asan_build, print_test_name
from .cpa_utils import DEFAULT_MONITOR_ARGS, get_first_cpa_records_from_test_dir, run_cpa_monitor
from .resource.run_workloads import run_workloads, terminate_workloads

pytestmark = [pytest.mark.usefixtures("print_test_name")]


def _build_monitor_command(output_dir: str, extra_args):
    current_args_dict = DEFAULT_MONITOR_ARGS.copy()

    i = 0
    while i < len(extra_args):
        arg_name = extra_args[i]
        if arg_name.startswith("--") and "=" in arg_name:
            key, value = arg_name.split("=", 1)
            current_args_dict[key] = value
            i += 1
            continue
        if arg_name.startswith("-") and i + 1 < len(extra_args) and not extra_args[i + 1].startswith("-"):
            current_args_dict[arg_name] = extra_args[i + 1]
            i += 2
            continue
        current_args_dict[arg_name] = ""
        i += 1

    if current_args_dict.get("--backend") == "perf":
        current_args_dict.pop("--stack_size", None)

    monitor_cmd_list = [CLI_BINARY, "monitor", "--store_dir", output_dir]
    for key, value in current_args_dict.items():
        if not value and key != "--duration":
            monitor_cmd_list.append(key)
            continue
        if value:
            if key.startswith("--"):
                monitor_cmd_list.append(f"{key}={value}")
            else:
                monitor_cmd_list.extend([key, value])
        elif key == "--duration":
            monitor_cmd_list.append(key)
    return monitor_cmd_list


def _read_process_cpu_ticks(pid: int) -> int:
    total_ticks = 0
    task_dir = f"/proc/{pid}/task"
    if not os.path.isdir(task_dir):
        return -1

    for tid in os.listdir(task_dir):
        stat_path = os.path.join(task_dir, tid, "stat")
        try:
            with open(stat_path, "r", encoding="utf-8") as f:
                line = f.read().strip()
        except OSError:
            continue

        comm_end = line.rfind(")")
        if comm_end < 0:
            continue
        fields = line[comm_end + 2 :].split()
        if len(fields) < 15:
            continue
        total_ticks += int(fields[11]) + int(fields[12])

    return total_ticks


def _sample_process_cpu_cores(pid: int, warmup_sec: float = 2.0, interval_sec: float = 0.5, steady_window_sec: float = 8.0):
    clk_tck = os.sysconf("SC_CLK_TCK")
    samples = []

    time.sleep(warmup_sec)
    last_ticks = _read_process_cpu_ticks(pid)
    last_time = time.monotonic()

    steps = int(steady_window_sec / interval_sec)
    for _ in range(steps):
        if last_ticks < 0:
            break
        time.sleep(interval_sec)
        now_time = time.monotonic()
        now_ticks = _read_process_cpu_ticks(pid)
        if now_ticks < 0:
            break
        delta_ticks = now_ticks - last_ticks
        delta_time = now_time - last_time
        if delta_time > 0:
            samples.append((delta_ticks / clk_tck) / delta_time)
        last_ticks = now_ticks
        last_time = now_time

    return samples


def _stack_contains_ordered_symbols(
    stack: List[str],
    expected_symbols: List[str],
) -> bool:
    """Return true when expected symbols appear in order, allowing extra frames."""
    if not expected_symbols:
        return True

    expected_idx = 0
    for frame in stack:
        if expected_symbols[expected_idx] in frame:
            expected_idx += 1
            if expected_idx == len(expected_symbols):
                return True

    return False


def _go_hot_stack_variants_for_arch(machine: str) -> List[List[str]]:
    deep_stack = [
        "main.go_path_a_process_data_entry",
        "main.go_path_a_process_data_stage_2",
        "main.go_path_a_process_data_stage_3",
        "main.go_path_a_process_data_stage_4",
    ]

    if machine in {"aarch64", "arm64"}:
        # The test ARM host uses Go 1.11 on arm64.  Its Go function prologues
        # save LR but do not maintain an x29 frame-pointer chain, while
        # libgunwinder intentionally does not consume Go runtime frame metadata.
        # A sampled hot Go symbol still verifies profiling and symbolization.
        arm_leaf_symbols = deep_stack + [
            "main.go_path_a_process_data_final",
        ]
        return [[symbol] for symbol in arm_leaf_symbols]

    return [deep_stack]


def _record_matches_expected_stack(record, expected_stack_variants):
    for expected_variant_parts in expected_stack_variants:
        if _stack_contains_ordered_symbols(record.stack, expected_variant_parts):
            return True
    return False


@pytest.mark.parametrize("backend", ["default", "perf"])
def test_cpa_multi_workload_hot_stacks_and_cpu_budget(tmp_path, backend):
    workload_names = ["sym_c", "sym_go", "rust_workload"]
    monitor_run_time_seconds = 12
    freq = 99
    workload_manager = None
    expected_hot_stacks = {
        "sym_c": [[
            "main",
            "c_path_a_calc_entry",
            "c_path_a_calc_stage_2",
            "c_path_a_calc_stage_3",
            "c_path_a_calc_stage_4",
            "c_path_a_calc_stage_5",
            "c_path_a_calc_stage_6",
            "c_path_a_calc_stage_7",
            "c_path_a_calc_stage_8",
            "c_path_a_calc_stage_9",
        ]],
        "sym_go": _go_hot_stack_variants_for_arch(platform.machine()),
        "rust_workload": [[
            "rust_workload::rust_path_a_compute_entry",
            "rust_workload::rust_path_a_compute_stage_2",
            "rust_workload::rust_path_a_compute_stage_3",
            "rust_workload::rust_path_a_compute_stage_4",
            "rust_workload::rust_path_a_compute_stage_5",
            "rust_workload::rust_path_a_compute_stage_6",
            "rust_workload::rust_path_a_compute_stage_7",
            "rust_workload::rust_path_a_compute_stage_8",
            "rust_workload::rust_path_a_compute_stage_9",
        ], [
            "rand_chacha::guts::refill_wide",
        ]],
    }

    try:
        workload_manager = run_workloads(workload_names)
        time.sleep(3)

        monitor_cmd = _build_monitor_command(
            str(tmp_path),
            [
                "--freq",
                str(freq),
                "--duration",
                str(monitor_run_time_seconds),
                *(["--backend", "perf"] if backend == "perf" else []),
            ],
        )
        monitor_proc = subprocess.Popen(
            monitor_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            cpu_samples = _sample_process_cpu_cores(monitor_proc.pid)
            stdout, stderr = monitor_proc.communicate(timeout=monitor_run_time_seconds + 20)
        except subprocess.TimeoutExpired:
            monitor_proc.kill()
            stdout, stderr = monitor_proc.communicate()
            raise AssertionError(f"cpa monitor timed out. stdout={stdout} stderr={stderr}")

        assert monitor_proc.returncode == 0, f"cpa monitor failed. stdout={stdout} stderr={stderr}"
        assert cpu_samples, "No CPU samples were collected for cpa monitor."

        mean_cpu_cores = sum(cpu_samples) / len(cpu_samples)
        logging.info(
            "cpa steady-state cpu cores samples=%s mean=%.3f backend=%s",
            cpu_samples,
            mean_cpu_cores,
            backend,
        )
        if not is_asan_build():
            assert mean_cpu_cores <= 0.5, f"cpa mean CPU usage exceeded budget: {mean_cpu_cores:.3f} cores"

        records = get_first_cpa_records_from_test_dir(str(tmp_path))
        assert records, f"No CPA records found in {tmp_path}."

        for workload_name, expected_variants in expected_hot_stacks.items():
            found = any(
                record.process_name == workload_name and _record_matches_expected_stack(record, expected_variants)
                for record in records
            )
            assert found, f"No expected hot stack found for workload {workload_name}."
    finally:
        if workload_manager:
            terminate_workloads(workload_manager)


@pytest.mark.parametrize("backend", ["default", "perf"])
def test_cpa_record_env_name(tmp_path, backend):
    pod_name_value = "my-test-pod-12345"
    workload_name = "sym_c_pod_env_test"
    workload_manager = None
    workload_pid = None

    try:
        workload_manager = run_workloads(
            [workload_name],
            custom_env_for_workload={workload_name: {"POD_NAME": pod_name_value}},
        )
        workload_pid = workload_manager.processes[0].pid
        time.sleep(2)

        extra_args = ["--freq", "99", "--duration", "8"]
        if backend == "default":
            extra_args.extend(["--pid", str(workload_pid)])
        if backend == "perf":
            extra_args.extend(["--backend", "perf"])
        run_cpa_monitor(str(tmp_path), run_time=8, extra_args=extra_args)

        records = get_first_cpa_records_from_test_dir(str(tmp_path))
        assert records, "No records exported for env-name test."

        relevant_records = [
            record
            for record in records
            if record.process_name == "sym_c" and record.pid == workload_pid
        ]
        assert relevant_records, "No sym_c records found in env-name test."

        total_samples = sum(record.samples for record in relevant_records)
        matched_samples = sum(
            record.samples for record in relevant_records if record.env_name == pod_name_value
        )

        logging.info(
            "env_name total_samples=%s matched_samples=%s backend=%s",
            total_samples,
            matched_samples,
            backend,
        )
        assert total_samples >= 50
        assert matched_samples / total_samples >= 0.8
    finally:
        if workload_manager:
            terminate_workloads(workload_manager)


@pytest.mark.parametrize("backend", ["default", "perf"])
def test_cpa_sym_go_anon_stack_resolution(tmp_path, backend):
    workload_name = "sym_go_anon"
    monitor_run_time_seconds = 8
    workload_manager = None
    workload_pid = None
    anon_exec_pattern = re.compile(r"0x[0-9a-fA-F]+ \[anon exec segment\]")
    expected_stack_variants = _go_hot_stack_variants_for_arch(platform.machine())

    try:
        workload_manager = run_workloads([workload_name])
        workload_pid = workload_manager.processes[0].pid
        time.sleep(3)

        extra_args = ["--freq", "99", "--duration", str(monitor_run_time_seconds)]
        if backend == "default":
            extra_args.extend(["--pid", str(workload_pid)])
        if backend == "perf":
            extra_args.extend(["--backend", "perf"])
        run_cpa_monitor(str(tmp_path), run_time=monitor_run_time_seconds, extra_args=extra_args)

        records = get_first_cpa_records_from_test_dir(str(tmp_path))
        assert records, f"No records exported for {workload_name}."

        relevant_records = [
            record
            for record in records
            if record.process_name == workload_name
            and record.pid == workload_pid
            and record.stack
        ]
        assert relevant_records, (
            f"No records found for {workload_name} pid={workload_pid}."
        )

        found_expected_stack = False
        anon_exec_records = 0
        for record in relevant_records:
            normalized_stack = [frame for frame in record.stack if frame]
            if not normalized_stack:
                continue

            if any(anon_exec_pattern.fullmatch(frame) for frame in normalized_stack):
                anon_exec_records += 1

            if _record_matches_expected_stack(record, expected_stack_variants):
                found_expected_stack = True
                break

        logging.info(
            "sym_go_anon records=%s anon_exec_records=%s backend=%s",
            len(relevant_records),
            anon_exec_records,
            backend,
        )
        assert found_expected_stack, (
            f"Expected Go hot stack was not found for backend={backend}."
        )
    finally:
        if workload_manager:
            terminate_workloads(workload_manager)
