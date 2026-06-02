# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

import os
import re
import signal
import struct
import subprocess
import time

import pytest

from .conftest import CLI_BINARY, is_asan_build, print_test_name, run_command
from .resource.run_workloads import run_workloads, terminate_workloads

pytestmark = [pytest.mark.usefixtures("print_test_name")]

FAKETIME_LIB = "/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1"
DEFAULT_WORKLOAD = "sym_c_cpu0"


def _require_faketime_support() -> None:
    if not os.path.exists(FAKETIME_LIB):
        pytest.skip("libfaketime is not installed on this machine.")
    if is_asan_build():
        pytest.skip("libfaketime tests are skipped when the CLI is built with ASAN.")


def _run_cpa_monitor_with_faketime(
    store_dir: str,
    faketime_spec: str,
    run_time: int,
    extra_args=None,
):
    merged_env = os.environ.copy()
    merged_env.update({
        "LD_PRELOAD": FAKETIME_LIB,
        "FAKETIME": faketime_spec,
    })
    args = [CLI_BINARY, "monitor", "--store_dir", store_dir]
    if extra_args:
        args.extend(extra_args)
    process = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=merged_env,
        cwd=store_dir,
    )
    stdout = ""
    stderr = ""
    forced_kill = False
    try:
        time.sleep(run_time)
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
        try:
            stdout, stderr = process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            forced_kill = True
    return_code = process.returncode
    allowed_codes = {0, -signal.SIGINT, 130}
    if forced_kill:
        allowed_codes.add(-signal.SIGKILL)
    assert return_code in allowed_codes, f"cpa monitor failed: stdout={stdout} stderr={stderr}"
    return stdout, stderr


def _list_store_dirs(base_dir: str):
    return sorted(
        entry
        for entry in os.listdir(base_dir)
        if os.path.isdir(os.path.join(base_dir, entry)) and entry.startswith("cpa_")
    )


def _write_fake_stackbin(file_path: str, records):
    with open(file_path, "wb") as f:
        for start_ms, end_ms, entries in records:
            f.write(b"\xFA\xFB")
            f.write(struct.pack("<QQQ", start_ms, end_ms, len(entries)))
            for ids_id, count in entries:
                f.write(struct.pack("<IQ", ids_id, count))
            f.write(b"\xFC\xFD")


def _prepare_fake_cpa_store(
    base_dir: str,
    records,
    strmap_entries,
    idsmap_entries,
):
    decompressed_dir = os.path.join(base_dir, "decompressed")
    os.makedirs(decompressed_dir, exist_ok=True)

    _write_fake_stackbin(os.path.join(decompressed_dir, "stack.bin"), records)

    with open(os.path.join(decompressed_dir, "strmap"), "w", encoding="utf-8") as f:
        for text, frame_id in strmap_entries:
            f.write(f"{text} {frame_id}\n")

    with open(os.path.join(decompressed_dir, "idsmap"), "w", encoding="utf-8") as f:
        for ids, ids_id in idsmap_entries:
            body = ";".join(str(item) for item in ids)
            f.write(f"{body}; {ids_id}\n")

    with open(os.path.join(base_dir, "conf"), "w", encoding="utf-8") as f:
        f.write("{}")


def test_cpa_monitor_rotates_store_directory_across_day_boundary(tmp_path):
    _require_faketime_support()

    workload_manager = None
    try:
        workload_manager = run_workloads([DEFAULT_WORKLOAD])
        _run_cpa_monitor_with_faketime(
            str(tmp_path),
            "@2025-12-16 23:59:00 x60",
            run_time=4,
        )

        store_dirs = _list_store_dirs(str(tmp_path))
        assert "cpa_251216" in store_dirs
        assert "cpa_251217" in store_dirs
    finally:
        if workload_manager:
            terminate_workloads(workload_manager)


def test_cpa_monitor_uses_start_suffix_for_second_same_day_store(tmp_path):
    _require_faketime_support()

    _run_cpa_monitor_with_faketime(
        str(tmp_path),
        "@2025-12-16 10:00:00",
        run_time=2,
    )
    _run_cpa_monitor_with_faketime(
        str(tmp_path),
        "@2025-12-16 12:34:56",
        run_time=2,
    )

    store_dirs = _list_store_dirs(str(tmp_path))
    assert "cpa_251216" in store_dirs
    assert "cpa_251216_start_123456" in store_dirs


def test_cpa_monitor_retention_policy_removes_expired_day_dir(tmp_path):
    _require_faketime_support()

    for day in ("2025-12-16", "2025-12-17", "2025-12-18"):
        _run_cpa_monitor_with_faketime(
            str(tmp_path),
            f"@{day} 10:00:00",
            run_time=2,
            extra_args=["--persistent_day", "1", "--backend", "perf"],
        )

    store_dirs = _list_store_dirs(str(tmp_path))
    assert "cpa_251216" not in store_dirs
    assert "cpa_251217" in store_dirs
    assert "cpa_251218" in store_dirs


def test_cpa_monitor_default_retention_removes_oldest_day_dir(tmp_path):
    _require_faketime_support()

    for day in (
        "2025-12-16",
        "2025-12-17",
        "2025-12-18",
        "2025-12-19",
        "2025-12-20",
        "2025-12-21",
        "2025-12-22",
        "2025-12-23",
        "2025-12-24",
    ):
        _run_cpa_monitor_with_faketime(
            str(tmp_path),
            f"@{day} 10:00:00",
            run_time=2,
            extra_args=["--backend", "perf"],
        )

    store_dirs = _list_store_dirs(str(tmp_path))
    assert "cpa_251216" not in store_dirs
    assert "cpa_251217" in store_dirs
    assert "cpa_251224" in store_dirs
    assert len(store_dirs) == 8


def test_cpa_show_range_reports_cross_day_window_from_store(tmp_path):
    store_dir = os.path.join(tmp_path, "cross-day-store")
    _prepare_fake_cpa_store(
        store_dir,
        records=[
            (23 * 3600 * 1000 + 59 * 60 * 1000 + 58 * 1000, 23 * 3600 * 1000 + 59 * 60 * 1000 + 59 * 1000, [(1, 2)]),
            (24 * 3600 * 1000, 24 * 3600 * 1000 + 3 * 1000, [(1, 3)]),
        ],
        strmap_entries=[("frameA", 1)],
        idsmap_entries=[([1], 1)],
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

    assert return_code == 0, f"cpa show --show_range failed: stdout={stdout} stderr={stderr}"
    assert "Records Num: 2" in stdout
    assert re.search(
        r"Record Time From \[ 23:59:58\.\d+ \] to \[ (?:00|24):00:03\.\d+ \]",
        stdout,
    ), stdout
