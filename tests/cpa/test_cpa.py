# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance


import logging
from typing import List

import pytest

from .conftest import cpa_backend, find_pid_by_name, get_cpu_of_pid, print_test_name
from .cpa_utils import CPARecord, get_cpa_records_info_from_test_dir, get_first_cpa_records_from_test_dir, run_cpa_monitor
from .resource.run_workloads import run_workloads, terminate_workloads

pytestmark = [pytest.mark.usefixtures("print_test_name")]


def test_cpa_freq(tmp_path, cpa_backend):
    """Sampling should capture the pinned workload at about the requested rate."""
    workload_name = "sym_c_cpu0"
    expected_cpu = "0"
    freq = 49
    monitor_run_time_seconds = 10
    cpa_output_dir = str(tmp_path)
    workload_manager = None

    try:
        workload_manager = run_workloads([workload_name])

        workload_pid = find_pid_by_name(workload_name)
        assert workload_pid is not None, f"PID for '{workload_name}' not found."
        assert get_cpu_of_pid(workload_pid) == expected_cpu

        extra_args = [
            "--freq",
            str(freq),
            "--log_print_cycles=300",
            "--duration",
            str(monitor_run_time_seconds),
        ]
        if cpa_backend == "perf":
            extra_args.extend(["--backend", "perf"])
        run_cpa_monitor(
            cpa_output_dir,
            run_time=monitor_run_time_seconds,
            extra_args=extra_args,
        )

        records_info = get_cpa_records_info_from_test_dir(cpa_output_dir)
        assert records_info is not None
        assert records_info.get("start_time")
        assert records_info.get("end_time")

        start_h, start_m, start_s = records_info["start_time"]
        end_h, end_m, end_s = records_info["end_time"]
        actual_start_seconds = start_h * 3600 + start_m * 60 + start_s
        actual_end_seconds = end_h * 3600 + end_m * 60 + end_s
        if actual_end_seconds < actual_start_seconds:
            actual_end_seconds += 24 * 3600

        actual_duration_seconds = actual_end_seconds - actual_start_seconds
        if actual_duration_seconds <= 0:
            actual_duration_seconds = monitor_run_time_seconds

        records = get_first_cpa_records_from_test_dir(cpa_output_dir)
        assert records, f"No CPA records found or parsed from {cpa_output_dir}."

        workload_records: List[CPARecord] = []
        for record in records:
            if record.process_name == workload_name:
                assert record.cpu_num == int(expected_cpu)
                workload_records.append(record)

        assert workload_records, f"No records found for workload '{workload_name}'."
        total_samples_for_workload = sum(record.samples for record in workload_records)
        expected_samples = freq * actual_duration_seconds
        min_expected_samples = max(freq, int(expected_samples * 0.7))
        max_expected_samples = int(expected_samples * 1.3) + freq

        logging.info(
            "freq=%s duration=%s total=%s expected=[%.2f, %.2f]",
            freq,
            actual_duration_seconds,
            total_samples_for_workload,
            min_expected_samples,
            max_expected_samples,
        )
        assert min_expected_samples <= total_samples_for_workload <= max_expected_samples
    finally:
        if workload_manager:
            terminate_workloads(workload_manager)
