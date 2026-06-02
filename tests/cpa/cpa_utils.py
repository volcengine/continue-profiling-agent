# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance


import os
import re
import logging
import subprocess
import time
import signal
from typing import List, Dict, Any, Optional

from .conftest import CLI_BINARY, run_command

DEFAULT_RUN_TIME = 5
MARKER_FRAME_RE = re.compile(r"^<#.*#>$")


class CPARecord:
    def __init__(self, line):
        stripped_line = line.strip()
        last_space_idx = stripped_line.rfind(" ")
        if last_space_idx == -1:
            logging.error(
                f"Could not find space to separate samples in line: '{stripped_line}'"
            )
            raise ValueError(
                f"Invalid CPARecord line format: Missing samples separator in '{stripped_line}'"
            )

        metadata_stack_part = stripped_line[:last_space_idx]
        samples_str = stripped_line[last_space_idx + 1 :]
        try:
            self.samples = int(samples_str)
        except ValueError as e:
            logging.error(
                f"Invalid samples string '{samples_str}' in line: '{stripped_line}'"
            )
            raise ValueError(
                f"Invalid samples string '{samples_str}' in CPARecord line: '{stripped_line}'. Error: {e}"
            )

        stack_split = metadata_stack_part.split(";")
        if not stack_split:
            raise ValueError(
                f"Invalid CPARecord line format: Missing metadata in '{stripped_line}'"
            )
        metadata_str = stack_split[0]
        self.stack = stack_split[1:]

        if len(metadata_str) < 30:
            raise ValueError(
                f"Invalid CPARecord line format: Metadata string too short in '{stripped_line}'. Expected at least 30 chars, got {len(metadata_str)}."
            )

        self.thread_name = metadata_str[:15].strip()
        self.process_name = metadata_str[15:30].strip()

        meta_details_str = metadata_str[30:]
        if meta_details_str.startswith("-"):
            meta_details_str = meta_details_str[1:]

        env_split = meta_details_str.split("|")
        self.env_name = env_split[1] if len(env_split) > 1 else ""

        id_cpu_pid_match = re.fullmatch(r"(\d+)-(\d+)-(-?\d+)", env_split[0])
        if not id_cpu_pid_match:
            raise ValueError(
                f"Invalid CPARecord line format: malformed cgroup_id, cpu_num, pid in '{env_split[0]}' from line '{stripped_line}'"
            )

        self.cgroup_id = int(id_cpu_pid_match.group(1))
        self.cpu_num = int(id_cpu_pid_match.group(2))
        self.pid = int(id_cpu_pid_match.group(3))

    def __repr__(self):
        return (
            f"CPARecord(thread='{self.thread_name}', proc='{self.process_name}', "
            f"cgroup='{self.cgroup_id}', cpu='{self.cpu_num}', pid='{self.pid}', env='{self.env_name}', "
            f"samples={self.samples}, stack={self.stack})"
        )


def parse_cpa_prof_file(
    prof_file_path: str, no_delete: bool = False
) -> List[CPARecord]:
    """
    Parses a .prof file and returns a list of CPARecord objects.
    If no_delete is True, the file will not be deleted after parsing.
    """
    records: List[CPARecord] = []
    if not os.path.exists(prof_file_path):
        logging.error(f".prof file not found at {prof_file_path}")
        return []

    try:
        with open(prof_file_path, "r", encoding="utf-8", errors="replace") as f:
            for line_number, line in enumerate(f, 1):
                if line.strip():
                    try:
                        records.append(CPARecord(line))
                    except Exception as e:
                        logging.error(
                            f"Failed to parse line {line_number}: '{line.strip()}'. Error: {e}"
                        )
    except (IOError, OSError) as e:
        logging.error(f"Error reading .prof file {prof_file_path}: {e}")

    assert_stack_markers_are_root_frames(records)

    if not no_delete:
        try:
            if os.path.exists(prof_file_path):
                os.remove(prof_file_path)
                logging.info(
                    f"Successfully deleted .prof file after parsing: {prof_file_path}"
                )
        except OSError as e:
            logging.error(
                f"Error deleting .prof file {prof_file_path} after parsing: {e}"
            )

    return records


def assert_stack_markers_are_root_frames(records: List[CPARecord]) -> None:
    """Reject synthetic sample markers that appear after normal frames."""
    for record in records:
        seen_normal_frame = False
        for index, frame in enumerate(record.stack):
            if MARKER_FRAME_RE.match(frame.strip()):
                if seen_normal_frame:
                    raise AssertionError(
                        "marker frame must be in the root stack layer before "
                        f"normal frames: pid={record.pid} marker={frame!r} "
                        f"index={index} stack={record.stack!r}"
                    )
                continue
            seen_normal_frame = True


def format_time_list_to_str(time_list: List[int]) -> str:
    """Converts a list [hh, mm, ss] to 'hh:mm:ss' string."""
    if len(time_list) == 3:
        return f"{time_list[0]:02d}:{time_list[1]:02d}:{time_list[2]:02d}"
    return ""


def get_cpa_records_info(actual_data_dir: str) -> Optional[Dict[str, Any]]:
    """
    Runs show on a specific profiling data directory to get record count, time range, stack type and .prof file name.
    Returns a dictionary with 'records_num', 'stack_type', 'prof_file_name', 'prof_file_path', 'start_time', 'end_time'.
    The .prof file is deleted after its path is obtained.
    """
    # This function expects the direct profile directory path.
    logging.info(f"Getting CPA records info from: {actual_data_dir}")

    cmd_get_num = ["show", "--read", actual_data_dir, "--show_range", "1"]
    stdout_num, stderr_num, ret_num = run_command(cmd_get_num)
    if ret_num != 0:
        logging.error(
            f"Failed to get record count from {actual_data_dir}. stderr: {stderr_num}"
        )
        return None

    records_num_match = re.search(r"Records Num: (\d+)", stdout_num)
    if not records_num_match:
        logging.error(f"Could not parse Records Num from output: {stdout_num}")
        return None
    records_num = int(records_num_match.group(1))

    start_time_list: Optional[List[int]] = None
    end_time_list: Optional[List[int]] = None
    time_range_match = re.search(
        r"Record Time From \[ (\d{2}):(\d{2}):(\d{2})\.\d+ \] to \[ (\d{2}):(\d{2}):(\d{2})\.\d+ \]",
        stdout_num,
    )
    if time_range_match:
        start_time_list = [
            int(time_range_match.group(1)),
            int(time_range_match.group(2)),
            int(time_range_match.group(3)),
        ]
        end_time_list = [
            int(time_range_match.group(4)),
            int(time_range_match.group(5)),
            int(time_range_match.group(6)),
        ]

    store_dir_path = actual_data_dir

    if records_num == 0:
        logging.info(
            f"No records found (Records Num: 0) in {store_dir_path}. Skipping .prof file retrieval."
        )
        return {
            "records_num": 0,
            "stack_type": -1,
            "prof_file_name": None,
            "prof_file_path": None,
            "start_time": start_time_list,
            "end_time": end_time_list,
        }

    prof_file_name = f"cpa_test_{records_num}.prof"
    prof_file_path = os.path.join(store_dir_path, prof_file_name)
    cmd_get_prof = [
        "show",
        "--read",
        store_dir_path,
        "--output_num",
        str(records_num),
        "--show_raw",
        "1",
        "--output_prof",
        prof_file_path,
    ]
    stdout_prof, stderr_prof, ret_prof = run_command(cmd_get_prof)
    if ret_prof != 0:
        logging.error(
            f"Failed to get .prof file info from {store_dir_path} with {records_num} records. stderr: {stderr_prof}"
        )
        return None

    stack_type_match = re.search(r"Stack Type (\d+)", stdout_prof)
    stack_type = int(stack_type_match.group(1)) if stack_type_match else -1

    found_prof_file_path = None
    # Check in store_dir_path itself first, then subdirectories, then known temp dir, then CWD
    potential_paths_to_check = [
        prof_file_path,
    ]
    for entry in os.listdir(store_dir_path):
        sub_dir_path = os.path.join(store_dir_path, entry)
        if os.path.isdir(sub_dir_path):
            potential_paths_to_check.append(os.path.join(sub_dir_path, prof_file_name))
    test_tmp_dir = os.environ.get("CPA_TEST_TMP_DIR")
    if test_tmp_dir:
        potential_paths_to_check.append(os.path.join(test_tmp_dir, prof_file_name))
    potential_paths_to_check.append(os.path.join(os.getcwd(), prof_file_name))

    for p_path in potential_paths_to_check:
        if os.path.exists(p_path):
            found_prof_file_path = p_path
            break

    if not found_prof_file_path:
        logging.error(
            f"Could not find .prof file '{prof_file_name}' in checked locations. Output: {stdout_prof}"
        )
        return None

    return {
        "records_num": records_num,
        "stack_type": stack_type,
        "prof_file_name": prof_file_name,
        "prof_file_path": found_prof_file_path,
        "start_time": start_time_list,
        "end_time": end_time_list,
    }


DEFAULT_MONITOR_ARGS = {
    "--freq": "49",
    "--log_print_cycles": "300",
    "--stack_size": "65536",
    "--record_env_name": "MY_POD_NAME,POD_NAME",
}


def run_cpa_monitor(
    cpa_test_dir: str,
    extra_args: Optional[List[str]] = None,
    run_time: int = 30,
    cwd: Optional[str] = None,
):
    """Run `cpa monitor` with default and overridden arguments."""
    current_args_dict = DEFAULT_MONITOR_ARGS.copy()
    is_duration_test = False
    is_oneshot_test = False

    if extra_args:
        i = 0
        while i < len(extra_args):
            arg_name = extra_args[i]
            if arg_name == "--duration":
                is_duration_test = True
            if arg_name == "--oneshot":
                is_oneshot_test = True

            # Handles --key=value
            if arg_name.startswith("--") and "=" in arg_name:
                key, value = arg_name.split("=", 1)
                current_args_dict[key] = value
                i += 1
                continue

            # Handles --key value or -k value
            if (
                arg_name.startswith("-")
                and i + 1 < len(extra_args)
                and not extra_args[i + 1].startswith("-")
            ):
                current_args_dict[arg_name] = extra_args[i + 1]
                i += 2
                continue

            # Handles --flag or -f
            if arg_name.startswith("-"):
                current_args_dict[arg_name] = ""
                i += 1
                continue

            logging.warning(f"Skipping malformed argument in extra_args: {arg_name}")
            i += 1

    # If neither --duration nor --oneshot is provided, enforce --duration using run_time
    # to avoid relying on SIGINT, which can cause flaky returns from the CLI.
    if not is_duration_test and not is_oneshot_test:
        current_args_dict["--duration"] = str(run_time)
        is_duration_test = True

    if current_args_dict.get("--backend") == "perf":
        current_args_dict.pop("--stack_size", None)

    monitor_cmd_list = [
        CLI_BINARY,
        "monitor",
    ]
    if not is_oneshot_test:
        monitor_cmd_list.extend(["--store_dir", cpa_test_dir])

    for key, value in current_args_dict.items():
        # This handles flags like --oneshot or -f
        if not value and key != "--duration":
            monitor_cmd_list.append(key)
            continue

        if value:
            # Handles --key=value
            if key.startswith("--"):
                monitor_cmd_list.append(f"{key}={value}")
            # Handles -k value
            else:
                monitor_cmd_list.append(key)
                monitor_cmd_list.append(value)
        # Handles --duration without a value
        elif key == "--duration" and not value:
            monitor_cmd_list.append(key)

    logging.info(f"Running monitor with command: {monitor_cmd_list}")
    monitor_proc = subprocess.Popen(
        monitor_cmd_list,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
    )

    m_stdout_bytes, m_stderr_bytes = b"", b""

    if (
        is_duration_test
    ):  # If --duration is part of the command, respect its timeout logic
        duration_value_str = current_args_dict.get("--duration")
        timeout_duration = None
        if duration_value_str and duration_value_str.isdigit():
            timeout_duration = (
                int(duration_value_str) + 15
            )  # Add buffer for --duration tests
        else:
            timeout_duration = (
                run_time + 15
            )  # Fallback if --duration is present but no value, or non-digit
        try:
            m_stdout_bytes, m_stderr_bytes = monitor_proc.communicate(
                timeout=timeout_duration
            )
        except subprocess.TimeoutExpired:
            monitor_proc.kill()
            m_stdout_bytes, m_stderr_bytes = monitor_proc.communicate()
            logging.warning(
                f"monitor with --duration timed out after {timeout_duration}s. Killed."
            )
    elif is_oneshot_test:
        try:
            m_stdout_bytes, m_stderr_bytes = monitor_proc.communicate(timeout=run_time)
        except subprocess.TimeoutExpired:
            logging.warning(
                f"monitor oneshot did not exit within {run_time}s. Sending SIGINT."
            )
            monitor_proc.send_signal(signal.SIGINT)
            try:
                m_stdout_bytes, m_stderr_bytes = monitor_proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                logging.warning(
                    "monitor oneshot did not terminate after SIGINT and 15s. Killing."
                )
                monitor_proc.kill()
                m_stdout_bytes, m_stderr_bytes = monitor_proc.communicate()
    else:  # Standard run_time logic (Ctrl+C equivalent)
        try:
            time.sleep(run_time)
        except KeyboardInterrupt:
            logging.info(
                "run_cpa_monitor interrupted by KeyboardInterrupt (simulated or actual)."
            )
        finally:
            if monitor_proc.poll() is None:  # Check if process is still running
                logging.info(
                    f"Sending SIGINT to monitor (PID: {monitor_proc.pid}) after {run_time}s."
                )
                monitor_proc.send_signal(signal.SIGINT)

            try:
                # Wait for a bit for the process to terminate gracefully after SIGINT
                m_stdout_bytes, m_stderr_bytes = monitor_proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                logging.warning(
                    f"monitor did not terminate after SIGINT and 15s. Killing."
                )
                monitor_proc.kill()
                m_stdout_bytes, m_stderr_bytes = monitor_proc.communicate()

    m_stdout = m_stdout_bytes.decode(errors="ignore")
    m_stderr = m_stderr_bytes.decode(errors="ignore")

    # Check return code. For SIGINT, it's often -signal.SIGINT or 130 on some systems.
    # If it's a --duration test, it should exit 0.
    if not is_duration_test:
        if is_oneshot_test and monitor_proc.returncode != 0:
            assert (
                False
            ), f"monitor oneshot failed. Expected exit code 0 but got {monitor_proc.returncode}. Stdout: {m_stdout}, Stderr: {m_stderr}"
        if monitor_proc.returncode not in [
            0,
            -signal.SIGINT,
            130,
        ]:  # 130 is exit code after Ctrl+C (SIGINT)
            assert (
                False
            ), f"monitor failed. Expected exit code 0, -{signal.SIGINT}, or 130 but got {monitor_proc.returncode}. Stdout: {m_stdout}, Stderr: {m_stderr}"
    elif is_duration_test and monitor_proc.returncode != 0:
        assert (
            False
        ), f"monitor --duration test failed with exit code {monitor_proc.returncode}. Stdout: {m_stdout}, Stderr: {m_stderr}"

    logging.info(f"monitor stdout: {m_stdout}")
    logging.info(f"monitor finished with code {monitor_proc.returncode}.")
    return m_stdout_bytes, m_stderr_bytes


def get_cpa_records_from_dir(
    actual_data_dir: str, pytestconfig: Optional[Any] = None
) -> List[CPARecord]:
    """
    Retrieves and parses records from a specific CPA data directory (e.g., cpa_xxxx).
    This function expects the direct path to the directory containing the .prof file.
    """
    logging.info(f"Getting CPA records from specific directory: {actual_data_dir}")
    records_info = get_cpa_records_info(
        actual_data_dir
    )  # This now takes actual_data_dir

    if not records_info:
        logging.error(
            f"Failed to get records info from {actual_data_dir}. Cannot parse records."
        )

    assert records_info is not None, f"Failed to get CPA records info from {actual_data_dir}"
    assert (
        records_info["records_num"] > 0
    ), f"Expected positive records_num, got {records_info['records_num']}"
    assert records_info["prof_file_name"].startswith("cpa_") and records_info["prof_file_name"].endswith(
        ".prof"
    )
    assert os.path.exists(
        records_info["prof_file_path"]
    ), f".prof file not found at {records_info['prof_file_path']}"

    # Check for errors or empty results from get_cpa_records_info
    if (
        not records_info
        or records_info.get("records_num", 0) == 0
        or not records_info.get("prof_file_path")
    ):
        logging.warning(
            f"Failed to get CPA records info, or no records/prof file from {actual_data_dir}. Returning empty list."
        )
        # If prof_file_path was None (e.g. records_num was 0), then nothing to parse or delete.
        # If prof_file_path existed but get_cpa_records_info decided not to return it (e.g. records_num was 0),
        # there's also nothing to parse or delete based on its output.
        return []

    # Proceed with parsing and deletion if records_info is valid and contains a prof_file_path
    prof_file_to_parse = records_info.get("prof_file_path")

    # This check is crucial: ensure the file path obtained is valid and the file exists *before* parsing
    if not prof_file_to_parse or not os.path.exists(prof_file_to_parse):
        logging.error(
            f".prof file {prof_file_to_parse if prof_file_to_parse else 'None'} (obtained from records_info) does not exist at parsing time. It might have been deleted prematurely or was never created properly."
        )
        return []

    # Respect pytest option to keep data if provided
    keep_data = False
    if pytestconfig is not None:
        try:
            keep_data = pytestconfig.getoption("--keep-cpa-data") or pytestconfig.getoption(
                "--no_delete_test_dir"
            )
        except Exception:
            keep_data = False

    parsed_records = parse_cpa_prof_file(
        prof_file_to_parse, no_delete=keep_data
    )

    # Ensure parsed_records is a list, even if parsing fails internally in parse_cpa_prof_file
    if parsed_records is None:  # parse_cpa_prof_file should return [] on error
        logging.error(
            f"parse_cpa_prof_file returned None for {prof_file_to_parse}. Defaulting to empty list."
        )
        parsed_records = []

    # Now delete the .prof file after parsing attempt
    if not keep_data:
        try:
            if os.path.exists(
                prof_file_to_parse
            ):  # Re-check existence before deletion, though it should exist if parsed
                os.remove(prof_file_to_parse)
                logging.info(
                    f"Successfully deleted .prof file after parsing: {prof_file_to_parse}"
                )
        except OSError as e:
            logging.error(
                f"Error deleting .prof file {prof_file_to_parse} after parsing: {e}"
            )
            # Decide if this error should prevent returning parsed_records.
            # For now, we'll return what we parsed, as deletion is a cleanup step.

    return parsed_records


def get_first_cpa_records_from_test_dir(
    cpa_test_dir: str, pytestconfig: Optional[Any] = None
) -> List[CPARecord]:
    """
    Wrapper to get records from the first CPA data subdirectory.
    Passes pytestconfig to control .prof file deletion.
    """
    logging.info(f"Looking for CPA data subdirectories in: {cpa_test_dir}")
    if not os.path.isdir(cpa_test_dir):
        logging.error(
            f"Provided cpa_test_dir is not a directory: {cpa_test_dir}"
        )
        return []

    subdirs = [
        d
        for d in os.listdir(cpa_test_dir)
        if os.path.isdir(os.path.join(cpa_test_dir, d)) and d.startswith("cpa_")
    ]
    if not subdirs:
        logging.error(
            f"No 'cpa_xxxx' subdirectories found in {cpa_test_dir} to process."
        )
        return []

    subdirs.sort()
    actual_data_dir_to_process = os.path.join(cpa_test_dir, subdirs[0])
    logging.info(
        f"Found CPA data directory: {actual_data_dir_to_process}. Processing it."
    )
    # Pass pytestconfig down
    return get_cpa_records_from_dir(actual_data_dir_to_process, pytestconfig)


def get_cpa_records_info_from_test_dir(
    cpa_test_dir: str,
) -> Optional[Dict[str, Any]]:
    """
    Wrapper function to get records info from the first CPA data subdirectory.
    """
    logging.info(
        f"Looking for CPA data subdirectories in: {cpa_test_dir} for info"
    )
    if not os.path.isdir(cpa_test_dir):
        logging.error(
            f"Provided cpa_test_dir is not a directory: {cpa_test_dir}"
        )
        return None

    subdirs = [
        d
        for d in os.listdir(cpa_test_dir)
        if os.path.isdir(os.path.join(cpa_test_dir, d)) and d.startswith("cpa_")
    ]
    if not subdirs:
        logging.error(
            f"No 'cpa_xxxx' subdirectories found in {cpa_test_dir} to get info from."
        )
        return None

    subdirs.sort()
    actual_data_dir_to_process = os.path.join(cpa_test_dir, subdirs[0])
    logging.info(
        f"Found CPA data directory for info: {actual_data_dir_to_process}. Getting info."
    )
    return get_cpa_records_info(actual_data_dir_to_process)
