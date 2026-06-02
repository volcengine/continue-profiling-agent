# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

import logging
import os
import struct
from typing import List, Tuple

import pytest

from .conftest import cpa_test_dir, print_test_name, run_command
from .cpa_utils import (
    CPARecord,
    get_cpa_records_info,
    get_first_cpa_records_from_test_dir,
    run_cpa_monitor,
)
from .resource.run_workloads import run_workloads, terminate_workloads

pytestmark = [pytest.mark.usefixtures("cpa_test_dir", "print_test_name")]

DEFAULT_WORKLOAD = "sym_c_cpu0"


def test_cpa_record_parser_accepts_negative_pid():
    record = CPARecord("<err read comm>               -0-36--1|SYSTEM;frame_[k] 1")

    assert record.thread_name == "<err read comm>"
    assert record.process_name == ""
    assert record.cgroup_id == 0
    assert record.cpu_num == 36
    assert record.pid == -1
    assert record.env_name == "SYSTEM"


def _write_fake_stackbin(file_path: str, records: List[Tuple[int, int, List[Tuple[int, int]]]]) -> None:
    """Write a minimal CPA stack.bin payload for tests."""
    with open(file_path, "wb") as f:
        for start_ns, end_ns, entries in records:
            f.write(b"\xFA\xFB")
            f.write(struct.pack("<QQQ", start_ns, end_ns, len(entries)))
            for ids_id, count in entries:
                f.write(struct.pack("<IQ", ids_id, count))
            f.write(b"\xFC\xFD")


def _prepare_fake_cpa_store(
    base_dir: str,
    records: List[Tuple[int, int, List[Tuple[int, int]]]],
    strmap_entries: List[Tuple[str, int]],
    idsmap_entries: List[Tuple[List[int], int]],
    include_stack_only: bool = False,
    include_conf: bool = True,
):
    decompressed_dir = os.path.join(base_dir, "decompressed")
    os.makedirs(decompressed_dir, exist_ok=True)

    if not include_stack_only:
        _write_fake_stackbin(os.path.join(decompressed_dir, "stack.bin"), records)

        with open(os.path.join(decompressed_dir, "strmap"), "w", encoding="utf-8") as f:
            for text, frame_id in strmap_entries:
                f.write(f"{text} {frame_id}\n")

        with open(os.path.join(decompressed_dir, "idsmap"), "w", encoding="utf-8") as f:
            for ids, ids_id in idsmap_entries:
                body = ";".join(str(item) for item in ids)
                f.write(f"{body}; {ids_id}\n")

    if include_conf:
        with open(os.path.join(base_dir, "conf"), "w", encoding="utf-8") as f:
            f.write("{}")

    return base_dir


def test_cpa_show_and_parse_prof(cpa_test_dir):
    """Basic end-to-end smoke test for `cpa monitor` output."""
    monitor_run_time_seconds = 3
    workload_manager = None

    try:
        logging.info("Starting workload: %s", DEFAULT_WORKLOAD)
        workload_manager = run_workloads([DEFAULT_WORKLOAD])

        logging.info(
            "Running cpa monitor for %ss in default dir: %s",
            monitor_run_time_seconds,
            cpa_test_dir,
        )
        run_cpa_monitor(
            cpa_test_dir,
            run_time=monitor_run_time_seconds,
            extra_args=["--duration", str(monitor_run_time_seconds)],
        )

        logging.info("Parsing records directly from %s for verification.", cpa_test_dir)
        records = get_first_cpa_records_from_test_dir(cpa_test_dir)
        assert records, f"Failed to parse records from {cpa_test_dir} using utility function."
        logging.info("Successfully parsed %s records from %s.", len(records), cpa_test_dir)

        for record in records:
            assert isinstance(record, CPARecord), f"Parsed item is not a CPARecord: {record}"
            assert record.process_name, f"Record has no process name: {record}"
            assert record.pid is not None, f"Record has no PID: {record}"
            assert record.cpu_num is not None, f"Record has no CPU number: {record}"
            assert record.samples >= 0, f"Record has negative samples: {record}"
    finally:
        if workload_manager:
            terminate_workloads(workload_manager)


def test_cpa_show_exports_flamegraph_records(tmp_path):
    """`cpa show` should export a flamegraph profile from recorded data."""
    monitor_run_time_seconds = 3
    workload_manager = None

    try:
        workload_manager = run_workloads([DEFAULT_WORKLOAD])
        run_cpa_monitor(
            str(tmp_path),
            run_time=monitor_run_time_seconds,
            extra_args=["--duration", str(monitor_run_time_seconds)],
        )

        data_dirs = sorted(
            entry
            for entry in os.listdir(tmp_path)
            if os.path.isdir(os.path.join(tmp_path, entry)) and entry.startswith("cpa_")
        )
        assert data_dirs, f"No CPA store directory found under {tmp_path}."

        data_dir = os.path.join(tmp_path, data_dirs[0])
        show_output = os.path.join(tmp_path, "show.prof")
        stdout, stderr, return_code = run_command(
            [
                "show",
                "--read",
                data_dir,
                "--output_num",
                "1",
                "--output_prof",
                show_output,
            ]
        )

        assert return_code == 0, f"cpa show failed with stderr: {stderr}\nStdout: {stdout}"
        assert os.path.exists(show_output), f"Expected exported profile at {show_output}."

        with open(show_output, "r", encoding="utf-8") as flamegraph_file:
            flamegraph = flamegraph_file.read()

        assert flamegraph.strip(), "cpa show exported an empty profile."
        assert f"SYSTEM;{DEFAULT_WORKLOAD}:" in flamegraph
        assert "main;" in flamegraph
    finally:
        if workload_manager:
            terminate_workloads(workload_manager)


def test_cpa_show_reject_non_positive_output_num(tmp_path):
    store_dir = os.path.join(tmp_path, "show-output-num")
    _prepare_fake_cpa_store(
        store_dir,
        records=[(0, 10, [(1, 1)])],
        strmap_entries=[("frameA", 1)],
        idsmap_entries=[([1], 1)],
    )

    stdout, stderr, return_code = run_command(
        [
            "show",
            "--read",
            store_dir,
            "--output_num",
            "0",
            "--use_cache",
            "1",
        ]
    )

    assert return_code != 0
    assert "output_num" in (stderr + stdout).lower()


def test_cpa_show_rejects_output_num_larger_than_record_count(tmp_path):
    store_dir = os.path.join(tmp_path, "show-output-too-large")
    _prepare_fake_cpa_store(
        store_dir,
        records=[(0, 10, [(1, 1)])],
        strmap_entries=[("frameA", 1)],
        idsmap_entries=[([1], 1)],
    )

    stdout, stderr, return_code = run_command(
        [
            "show",
            "--read",
            store_dir,
            "--output_num",
            "2",
            "--use_cache",
            "1",
        ]
    )

    assert return_code != 0
    assert "not found enough records" in (stderr + stdout).lower()


def test_cpa_show_rejects_invalid_time_format(tmp_path):
    store_dir = os.path.join(tmp_path, "show-invalid-time")
    _prepare_fake_cpa_store(
        store_dir,
        records=[(0, 10, [(1, 1)])],
        strmap_entries=[("frameA", 1)],
        idsmap_entries=[([1], 1)],
    )

    stdout, stderr, return_code = run_command(
        [
            "show",
            "--read",
            store_dir,
            "--starttime",
            "bad-format",
            "--use_cache",
            "1",
        ]
    )

    assert return_code != 0
    assert "invalid time" in (stderr + stdout).lower()


def test_cpa_show_rejects_reversed_time_range(tmp_path):
    store_dir = os.path.join(tmp_path, "show-reversed-range")
    _prepare_fake_cpa_store(
        store_dir,
        records=[(0, 10_000, [(1, 1)])],
        strmap_entries=[("frameA", 1)],
        idsmap_entries=[([1], 1)],
    )

    stdout, stderr, return_code = run_command(
        [
            "show",
            "--read",
            store_dir,
            "--starttime",
            "00:00:10",
            "--endtime",
            "00:00:05",
            "--use_cache",
            "1",
        ]
    )

    assert return_code != 0
    assert "time range not corrent" in (stderr + stdout).lower()


def test_cpa_show_handle_empty_stack_bin(tmp_path):
    store_dir = os.path.join(tmp_path, "show-empty-stack")
    _prepare_fake_cpa_store(
        store_dir,
        records=[],
        strmap_entries=[],
        idsmap_entries=[],
    )

    stdout, stderr, return_code = run_command(
        [
            "show",
            "--read",
            store_dir,
            "--show_range",
            "1",
            "--use_cache",
            "1",
        ]
    )

    assert return_code != 0
    assert "no valid records" in (stderr + stdout).lower()


def test_cpa_show_rejects_missing_store_dir(tmp_path):
    missing_dir = os.path.join(tmp_path, "does-not-exist")

    stdout, stderr, return_code = run_command(
        [
            "show",
            "--read",
            missing_dir,
            "--show_range",
            "1",
        ]
    )

    assert return_code != 0
    full_output = (stdout + stderr).lower()
    assert "failed to open input file" in full_output
    assert "failed to decompress stack.bin" in full_output


def test_cpa_show_stops_on_metadata_reload_failure(tmp_path):
    store_dir = os.path.join(tmp_path, "show-reload-fail")
    _prepare_fake_cpa_store(
        store_dir,
        records=[(0, 10, [(1, 1)])],
        strmap_entries=[("frameA", 1)],
        idsmap_entries=[([1], 1)],
    )

    # Keep only stack and ids mapping in cache, and make strmap cache absent to force
    # decompression/load failure for strmap while still letting dump_info parse.
    os.remove(os.path.join(store_dir, "decompressed", "strmap"))

    stdout, stderr, return_code = run_command(
        [
            "show",
            "--read",
            store_dir,
            "--use_cache",
            "1",
        ]
    )

    assert return_code != 0
    assert ("decompress" in (stderr + stdout).lower()) or ("not found" in (stderr + stdout).lower())


def test_cpa_show_split_tolerates_missing_stack_symbol_name(tmp_path):
    store_dir = os.path.join(tmp_path, "show-split-missing-id")
    _prepare_fake_cpa_store(
        store_dir,
        records=[(0, 10, [(2, 3)])],
        strmap_entries=[("known", 1)],
        idsmap_entries=[([99, 2], 2)],
    )

    split_dir = os.path.join(tmp_path, "split-out")
    os.makedirs(split_dir, exist_ok=True)

    # Remove known mapping for 99 in strmap to exercise missing id->str handling.
    with open(os.path.join(store_dir, "decompressed", "strmap"), "w", encoding="utf-8") as f:
        f.write("known 1\n")

    stdout, stderr, return_code = run_command(
        [
            "show",
            "--read",
            store_dir,
            "--output_num",
            "1",
            "--split_path",
            split_dir,
            "--use_cache",
            "1",
        ]
    )

    assert return_code == 0, f"cpa show split failed: stdout={stdout} stderr={stderr}"
    assert os.path.exists(os.path.join(split_dir, "strmap"))
    assert os.path.exists(os.path.join(split_dir, "idsmap"))
    assert os.path.exists(os.path.join(split_dir, "stack.bin"))
    with open(os.path.join(split_dir, "strmap"), "rb") as f:
        str_contents = f.read()
    assert b"<# STRMAP LOST ID #>" in str_contents


def test_cpa_show_range_reports_record_window(tmp_path):
    """`cpa show --show_range` should report record count and time range."""
    monitor_run_time_seconds = 3
    workload_manager = None

    try:
        workload_manager = run_workloads([DEFAULT_WORKLOAD])
        run_cpa_monitor(
            str(tmp_path),
            run_time=monitor_run_time_seconds,
            extra_args=["--duration", str(monitor_run_time_seconds)],
        )

        data_dirs = sorted(
            entry
            for entry in os.listdir(tmp_path)
            if os.path.isdir(os.path.join(tmp_path, entry)) and entry.startswith("cpa_")
        )
        assert data_dirs, f"No CPA store directory found under {tmp_path}."

        info = get_cpa_records_info(os.path.join(tmp_path, data_dirs[0]))
        assert info is not None, "cpa show did not return range information."
        assert info["records_num"] > 0
        assert info["start_time"] is not None
        assert info["end_time"] is not None
        assert info["prof_file_path"] is not None
        assert os.path.exists(info["prof_file_path"])
    finally:
        if workload_manager:
            terminate_workloads(workload_manager)


def test_cpa_monitor_oneshot_uses_default_output_prof_name(tmp_path):
    workload_manager = None

    try:
        workload_manager = run_workloads([DEFAULT_WORKLOAD])
        run_cpa_monitor(
            str(tmp_path),
            cwd=str(tmp_path),
            run_time=6,
            extra_args=[
                "--oneshot",
                "--duration=3",
            ],
        )

        default_prof = os.path.join(tmp_path, "cpa.prof")
        assert os.path.exists(default_prof), f"Expected default oneshot output at {default_prof}."
        with open(default_prof, "r", encoding="utf-8") as flamegraph_file:
            flamegraph = flamegraph_file.read()
        assert flamegraph.strip(), "default oneshot cpa.prof is empty."
    finally:
        if workload_manager:
            terminate_workloads(workload_manager)


def test_cpa_show_target_pid_filters_records(tmp_path):
    workload_manager = None

    try:
        workload_manager = run_workloads(["sym_c"])
        target_pid = workload_manager.processes[0].pid

        run_cpa_monitor(
            str(tmp_path),
            run_time=3,
            extra_args=["--duration", "3"],
        )

        data_dirs = sorted(
            entry
            for entry in os.listdir(tmp_path)
            if os.path.isdir(os.path.join(tmp_path, entry)) and entry.startswith("cpa_")
        )
        assert data_dirs, f"No CPA store directory found under {tmp_path}."

        data_dir = os.path.join(tmp_path, data_dirs[0])
        records_info = get_cpa_records_info(data_dir)
        assert records_info is not None

        output_prof = os.path.join(tmp_path, "target-pid.prof")
        stdout, stderr, return_code = run_command(
            [
                "show",
                "--read",
                data_dir,
                "--output_num",
                str(records_info["records_num"]),
                "--output_prof",
                output_prof,
                "--target_pid",
                str(target_pid),
            ]
        )

        assert return_code == 0, f"target_pid show failed: stdout={stdout} stderr={stderr}"
        with open(output_prof, "r", encoding="utf-8") as f:
            exported_lines = [line.strip() for line in f if line.strip()]

        assert exported_lines, "target_pid filter exported no records."
        assert all(f":{target_pid};" in line for line in exported_lines)
    finally:
        if workload_manager:
            terminate_workloads(workload_manager)


def test_cpa_show_target_env_filters_records(tmp_path):
    pod_name_value = "show-filter-pod"
    workload_manager = None

    try:
        workload_manager = run_workloads(
            ["sym_c_pod_env_test"],
            custom_env_for_workload={"sym_c_pod_env_test": {"POD_NAME": pod_name_value}},
        )

        run_cpa_monitor(
            str(tmp_path),
            run_time=3,
            extra_args=["--duration", "3"],
        )

        data_dirs = sorted(
            entry
            for entry in os.listdir(tmp_path)
            if os.path.isdir(os.path.join(tmp_path, entry)) and entry.startswith("cpa_")
        )
        assert data_dirs, f"No CPA store directory found under {tmp_path}."

        data_dir = os.path.join(tmp_path, data_dirs[0])
        records_info = get_cpa_records_info(data_dir)
        assert records_info is not None

        output_prof = os.path.join(tmp_path, "target-env.prof")
        stdout, stderr, return_code = run_command(
            [
                "show",
                "--read",
                data_dir,
                "--output_num",
                str(records_info["records_num"]),
                "--output_prof",
                output_prof,
                "--target_env",
                pod_name_value,
            ]
        )

        assert return_code == 0, f"target_env show failed: stdout={stdout} stderr={stderr}"
        with open(output_prof, "r", encoding="utf-8") as f:
            exported_lines = [line.strip() for line in f if line.strip()]

        assert exported_lines, "target_env filter exported no records."
        assert all(line.startswith(f"{pod_name_value};") for line in exported_lines)
    finally:
        if workload_manager:
            terminate_workloads(workload_manager)
