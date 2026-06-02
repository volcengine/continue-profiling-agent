# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

import logging
import os
import select
import subprocess
import threading
import time
import pytest

from .conftest import CLI_BINARY, RESOURCE_DIR
from .cpa_utils import DEFAULT_MONITOR_ARGS, get_first_cpa_records_from_test_dir

KSYMS_RELOAD_MESSAGE = "kallsyms digest changed, need reload."


def _compile_cpu_hogger_if_needed(output_dir: str) -> str:
    ko_path = os.path.join(output_dir, "cpu_hogger.ko")
    if os.path.exists(ko_path):
        return ko_path

    compile_script = os.path.join(RESOURCE_DIR, "compile_workloads.sh")
    if not os.path.exists(compile_script):
        return ""

    logging.info("cpu_hogger.ko not found, invoking %s", compile_script)
    compile_proc = subprocess.run(
        ["bash", compile_script],
        capture_output=True,
        text=True,
        check=False,
    )
    if compile_proc.returncode != 0:
        logging.warning(
            "compile_workloads.sh failed with rc=%s, stderr=%s",
            compile_proc.returncode,
            compile_proc.stderr.strip(),
        )
        return ""

    return ko_path if os.path.exists(ko_path) else ""


def _run_insmod_later(ko_path: str, delay_sec: int, result: dict) -> None:
    time.sleep(delay_sec)
    try:
        proc = subprocess.run(
            ["insmod", ko_path],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0:
            result["ok"] = True
            result["time"] = time.time()
            logging.info("insmod succeeded: %s", ko_path)
        else:
            result["error"] = proc.stderr.strip() or proc.stdout.strip() or "unknown error"
            logging.warning("insmod failed (rc=%s): %s", proc.returncode, result["error"])
    except Exception as exc:
        result["error"] = str(exc)
        logging.warning("insmod exception: %s", exc)


def _run_rmmod(module_name: str) -> None:
    if not module_name:
        return
    try:
        subprocess.run(["rmmod", module_name], capture_output=True, text=True, check=False)
    except Exception as exc:
        logging.warning("rmmod exception for %s: %s", module_name, exc)


def _build_monitor_command(output_dir: str, duration_sec: int) -> list[str]:
    cmd = [CLI_BINARY, "monitor", "--store_dir", output_dir]
    for key, value in DEFAULT_MONITOR_ARGS.items():
        if key == "--stack_size":
            continue
        if value:
            if key.startswith("--"):
                cmd.append(f"{key}={value}")
            else:
                cmd.extend([key, value])
        else:
            cmd.append(key)
    cmd.extend(["--duration", str(duration_sec)])
    return cmd


def _run_monitor_and_collect(command: list[str], run_seconds: int):
    start = time.time()
    proc = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    marker_seen_time = None
    output_lines = []
    deadline = start + run_seconds + 20

    try:
        while True:
            now = time.time()
            if now >= deadline:
                logging.warning("monitor run reached hard timeout, killing cpa monitor process.")
                proc.kill()
                break

            if proc.stdout is None:
                break

            remaining = deadline - now
            rlist, _, _ = select.select([proc.stdout], [], [], remaining)
            if not rlist:
                if proc.poll() is not None:
                    break
                continue

            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    break
                continue

            output_lines.append(line)
            if marker_seen_time is None and KSYMS_RELOAD_MESSAGE in line:
                marker_seen_time = time.time() - start

            # Keep loop running until process exits; duration mode should self-terminate.
            if proc.poll() is not None:
                break

        # Drain any remaining buffered lines after process exits.
        if proc.stdout is not None:
            leftover = proc.stdout.read()
            if leftover:
                output_lines.append(leftover)
    finally:
        if proc.stdout is not None:
            proc.stdout.close()

    try:
        return_code = proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        logging.warning("monitor did not exit cleanly after signal/kill; forcing kill.")
        proc.kill()
        return_code = proc.returncode

    return "".join(output_lines), marker_seen_time, return_code


@pytest.mark.usefixtures("print_test_name")
def test_ksyms_reload_after_cpu_hogger_insert(tmp_path):
    if os.geteuid() != 0:
        pytest.skip("Root privileges are required for insmod/rmmod and ksyms reload behavior.")

    ko_path = _compile_cpu_hogger_if_needed(os.path.join(RESOURCE_DIR, "output"))
    if not ko_path:
        pytest.skip("cpu_hogger.ko is missing; place or compile tests/cpa/resource/output/cpu_hogger.ko.")

    if subprocess.run(["which", "insmod"], capture_output=True, text=True).returncode != 0:
        pytest.skip("insmod is unavailable; cannot test ksyms reload behavior.")

    monitor_run_time = 80
    insmod_delay = 5

    insmod_result = {"ok": False, "error": "", "time": None}
    insmod_thread = threading.Thread(
        target=_run_insmod_later,
        args=(ko_path, insmod_delay, insmod_result),
        daemon=True,
    )
    insmod_thread.start()

    try:
        monitor_cmd = _build_monitor_command(str(tmp_path), monitor_run_time)
        logging.info(
            "Running cpa monitor for %ss: %s",
            monitor_run_time,
            " ".join(monitor_cmd),
        )
        stdout_text, marker_time, return_code = _run_monitor_and_collect(
            monitor_cmd,
            monitor_run_time,
        )

        insmod_thread.join(timeout=5)
        if not insmod_result.get("ok"):
            pytest.skip(f"cpu_hogger insertion failed: {insmod_result.get('error')}")

        assert (
            return_code == 0
        ), f"cpa monitor exited with {return_code}. output:\n{stdout_text[:4000]}"
        assert marker_time is not None, (
            "Expected ksyms reload log not found. "
            "Output:\n"
            f"{stdout_text[:4000]}"
        )
        assert (
            marker_time >= insmod_delay
        ), f"kallsyms reload marker happened too early ({marker_time:.2f}s), expected after delayed insert at {insmod_delay}s."

        records = get_first_cpa_records_from_test_dir(str(tmp_path))
        assert records, f"No CPA records parsed from {tmp_path}. Output:\n{stdout_text[:4000]}"

        tokens = (
            "cpu_hogger",
            "path_a_core_computation",
            "path_b_generate_response_data",
        )
        found = any(
            any(token in frame for frame in record.stack)
            for record in records
            for token in tokens
        )
        assert found, (
            "No cpu_hogger-related frame found in exported records. "
            "Captured records may not include the delayed module workload."
        )
    finally:
        insmod_thread.join(timeout=5)
        _run_rmmod("cpu_hogger")
