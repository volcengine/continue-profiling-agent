# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

import logging
import os
import subprocess
import threading
import time

import pytest

from .conftest import RESOURCE_DIR, print_test_name
from .cpa_utils import get_first_cpa_records_from_test_dir, run_cpa_monitor

pytestmark = [pytest.mark.usefixtures("print_test_name")]

OUTPUT_DIR = os.path.join(RESOURCE_DIR, "output")
COMPILE_SCRIPT = os.path.join(RESOURCE_DIR, "compile_workloads.sh")


def _ensure_kernel_module(module_file: str) -> str:
    module_path = os.path.join(OUTPUT_DIR, module_file)
    if os.path.exists(module_path):
        return module_path

    if os.path.exists(COMPILE_SCRIPT):
        subprocess.run(["bash", COMPILE_SCRIPT], check=False, text=True)

    if os.path.exists(module_path):
        return module_path

    pytest.skip(f"Kernel module test asset is not available: {module_file}")


def _require_module_test_prereqs() -> None:
    if os.geteuid() != 0:
        pytest.skip("Kernel module tests require root privileges.")


def _module_is_loaded(module_name: str) -> bool:
    result = subprocess.run(["lsmod"], capture_output=True, text=True, check=False)
    return module_name in result.stdout


def _try_rmmod(module_name: str) -> None:
    if not module_name:
        return
    if not _module_is_loaded(module_name):
        return
    subprocess.run(["rmmod", module_name], capture_output=True, text=True, check=False)


def _trigger_irqoff_window(
    ko_path: str,
    insmod_delay_seconds: float,
    irqoff_duration_seconds: int,
    cpu_to_lock: int,
) -> None:
    time.sleep(insmod_delay_seconds)

    if not os.path.exists(ko_path):
        return

    subprocess.run(
        [
            "taskset",
            "-c",
            str(cpu_to_lock),
            "insmod",
            ko_path,
            f"time_secs={irqoff_duration_seconds}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    time.sleep(irqoff_duration_seconds + 2)


def test_cpa_kworker_module_frames_are_captured(tmp_path):
    _require_module_test_prereqs()

    ko_path = _ensure_kernel_module("cpu_hogger.ko")
    module_name = os.path.splitext(os.path.basename(ko_path))[0]
    monitor_run_time_seconds = 10
    effective_kworker_sample_duration_seconds = monitor_run_time_seconds * 0.5
    freq = 99
    sample_tolerance_ratio = 0.35
    expected_functions = [
        "path_a_data_processing_pipeline_[k]",
        "path_b_network_request_handler_[k]",
    ]

    _try_rmmod(module_name)
    insmod_proc = subprocess.run(["insmod", ko_path], capture_output=True, text=True, check=False)
    if insmod_proc.returncode != 0:
        pytest.skip(f"Failed to insmod {module_name}: {insmod_proc.stderr.strip()}")

    try:
        time.sleep(1)
        run_cpa_monitor(
            str(tmp_path),
            run_time=monitor_run_time_seconds,
            extra_args=["--freq", str(freq), "--duration", str(monitor_run_time_seconds)],
        )

        records = get_first_cpa_records_from_test_dir(str(tmp_path))
        assert records, "No records exported for kworker test."

        total_kworker_samples = 0
        found_kworker_records = False
        for record in records:
            for stack_frame in record.stack:
                if any(func_name in stack_frame for func_name in expected_functions):
                    total_kworker_samples += record.samples
                    found_kworker_records = True
                    break

        assert found_kworker_records, "No expected kworker frames were found in exported stacks."

        expected_samples = freq * effective_kworker_sample_duration_seconds
        min_expected_samples = expected_samples * (1 - sample_tolerance_ratio)
        max_expected_samples = expected_samples * (1 + sample_tolerance_ratio)

        logging.info(
            "kworker samples=%s expected_range=[%.2f, %.2f]",
            total_kworker_samples,
            min_expected_samples,
            max_expected_samples,
        )
        assert min_expected_samples <= total_kworker_samples <= max_expected_samples
    finally:
        time.sleep(1)
        _try_rmmod(module_name)


def test_cpa_irqoff_samples_are_captured_on_bpf_backend(tmp_path):
    _require_module_test_prereqs()

    ko_path = _ensure_kernel_module("test_irq_disable.ko")
    monitor_run_time_seconds = 30
    irqoff_duration_seconds = 1
    cpu_to_lock = 1
    freq = 99
    sample_tolerance_ratio = 0.25
    irqoff_stack_signature = f"<# IRQOFF SAMPLE ON CPU {cpu_to_lock} #>"

    insmod_delay_seconds = (monitor_run_time_seconds / 2.0) - (irqoff_duration_seconds / 2.0)
    if insmod_delay_seconds < 0:
        insmod_delay_seconds = 0

    irqoff_thread = threading.Thread(
        target=_trigger_irqoff_window,
        args=(ko_path, insmod_delay_seconds, irqoff_duration_seconds, cpu_to_lock),
    )
    irqoff_thread.start()

    try:
        run_cpa_monitor(
            str(tmp_path),
            run_time=monitor_run_time_seconds,
            extra_args=[
                "--backend=bpf",
                "--freq",
                str(freq),
                "--duration",
                str(monitor_run_time_seconds),
            ],
        )
    finally:
        irqoff_thread.join(timeout=insmod_delay_seconds + irqoff_duration_seconds + 10)

    records = get_first_cpa_records_from_test_dir(str(tmp_path))
    assert records, "No records exported for IRQOFF test."

    irqoff_samples_count = 0
    found_records_for_target_cpu = False
    for record in records:
        if record.cpu_num != cpu_to_lock:
            continue

        found_records_for_target_cpu = True
        if irqoff_stack_signature in record.stack:
            irqoff_samples_count += record.samples

    assert found_records_for_target_cpu, f"No records were exported for CPU {cpu_to_lock}."

    expected_samples = freq * irqoff_duration_seconds
    min_expected_samples = expected_samples * (1 - sample_tolerance_ratio)
    max_expected_samples = expected_samples * (1 + sample_tolerance_ratio)

    logging.info(
        "irqoff samples=%s expected_range=[%.2f, %.2f]",
        irqoff_samples_count,
        min_expected_samples,
        max_expected_samples,
    )
    assert min_expected_samples <= irqoff_samples_count <= max_expected_samples
