# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance


import functools
import pytest
import subprocess
import os
import shutil
import logging

# Configure basic logging for all tests
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def _resolve_binary_path() -> str:
    candidates = [
        os.environ.get("TEST_CPA_PATH"),
        os.environ.get("TEST_CLI_PATH"),
        os.path.join(REPO_ROOT, "build", "bin", "cpa"),
    ]
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return candidate
    return candidates[0] or candidates[1] or candidates[2]


CLI_BINARY = _resolve_binary_path()

RESOURCE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resource")
TEST_CPA_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "test_cpa_data"
)
RUN_WORKLOADS_SCRIPT = os.path.join(RESOURCE_DIR, "run_workloads.py")


@functools.lru_cache(maxsize=1)
def is_asan_build() -> bool:
    explicit = os.environ.get("TEST_CPA_ASAN")
    if explicit is not None:
        return explicit.lower() in {"1", "true", "yes", "on"}

    try:
        result = subprocess.run(
            ["nm", CLI_BINARY],
            stdout=subprocess.PIPE,
            text=True,
            check=False,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return False

    if result.returncode != 0:
        return False

    return "__asan_init" in result.stdout or "__asan_report" in result.stdout


def find_pid_by_name(process_name_part):
    """Finds a PID by a part of its command name. Returns PID as string or None."""
    try:
        result = subprocess.run(
            ["pgrep", "-f", process_name_part, "-n"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        print(f"Could not find PID for process containing '{process_name_part}'.")
        return None
    except FileNotFoundError:
        print("pgrep command not found. Cannot find PID by name.")
        return None


def get_cpu_of_pid(pid):
    """Get the CPU core a PID is running on. Linux specific using ps."""
    if not pid:
        return None
    try:
        result = subprocess.run(
            ["ps", "-o", "psr", "-p", str(pid)],
            capture_output=True,
            text=True,
            check=True,
        )
        lines = result.stdout.strip().split("\n")
        if len(lines) > 1:
            return lines[1].strip()  # PSR is the CPU core
        return None
    except subprocess.CalledProcessError:
        print(f"Could not get CPU for PID {pid}.")
        return None
    except FileNotFoundError:
        print("ps command not found. Cannot get CPU for PID.")
        return None


def run_command(command_args, timeout=60, env=None, cwd=None):
    """Helper function to run CLI commands and return their output."""
    try:
        merged_env = None
        if env is not None:
            merged_env = os.environ.copy()
            merged_env.update(env)
        if cwd is None:
            cwd = os.environ.get("CPA_TEST_TMP_DIR")
        # CLI_BINARY should be part of command_args passed by the caller
        logging.info("Run [" + " ".join([CLI_BINARY] + command_args) + "]")
        process = subprocess.Popen(
            [CLI_BINARY] + command_args,  # Use command_args directly
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=merged_env,
            cwd=cwd,
        )
        stdout, stderr = process.communicate(timeout=timeout)
        return_code = process.returncode
        return stdout, stderr, return_code
    except FileNotFoundError:
        pytest.fail(
        f"CPA binary not found at {CLI_BINARY}. Please build the project or check the binary path."
        )
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        command_str = " ".join(command_args)
        pytest.fail(
            f"Command '{command_str}' timed out after {timeout} seconds.\nStdout: {stdout}\nStderr: {stderr}"
        )
    except Exception as e:
        command_str = " ".join(command_args)
        pytest.fail(f"Command '{command_str}' failed with exception: {e}")


def pytest_addoption(parser):
    parser.addoption(
        "--keep-cpa-data",
        action="store_true",
        default=False,
        help="Keep CPA data and test directory after tests run",
    )
    parser.addoption(
        "--no_delete_test_dir",
        action="store_true",
        default=False,
        help="Do not delete test directory after tests run. Alias for --keep-cpa-data.",
    )

@pytest.fixture(params=["default", "perf"])
def cpa_backend(request):
    """Parameterize CPA backend: 'default' (no --backend) and 'perf'."""
    return request.param


@pytest.fixture
def cpa_test_dir(request):
    """Creates and cleans up the CPA test directory."""
    keep_data = request.config.getoption(
        "--keep-cpa-data"
    ) or request.config.getoption("--no_delete_test_dir")

    if os.path.exists(TEST_CPA_DIR):
        if not keep_data:
            shutil.rmtree(TEST_CPA_DIR)
            os.makedirs(TEST_CPA_DIR, exist_ok=True)
        else:
            # If keeping data, and directory exists, we might want to clear previous prof files
            # or use a subdirectory for each test run to avoid conflicts.
            # For now, just log that we are reusing it.
            logging.info(
                f"Reusing existing TEST_CPA_DIR: {TEST_CPA_DIR} due to --keep-cpa-data."
            )
            # Optionally, clean up .prof files if the directory is being reused
            # for item in os.listdir(TEST_CPA_DIR):
            #     if item.endswith(".prof"):
            #         os.remove(os.path.join(TEST_CPA_DIR, item))
    else:
        os.makedirs(TEST_CPA_DIR, exist_ok=True)

    def cleanup_cpa_dir():
        if not keep_data:
            if os.path.exists(TEST_CPA_DIR):
                shutil.rmtree(TEST_CPA_DIR)
                logging.info(f"Cleaned up TEST_CPA_DIR: {TEST_CPA_DIR}")
        else:
            logging.info(
                f"Keeping TEST_CPA_DIR: {TEST_CPA_DIR} as requested by --keep-cpa-data."
            )
            # Also, if keeping data, we might not want to delete .prof files specifically
            # The user might want to inspect them.

    request.addfinalizer(cleanup_cpa_dir)
    return TEST_CPA_DIR

@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    # execute all other hooks to obtain the report object
    outcome = yield
    rep = outcome.get_result()

    # set a report attribute for each phase of a call, which can
    # be "setup", "call", "teardown"
    setattr(item, "rep_" + rep.when, rep)


@pytest.fixture
def print_test_name(request):
    print(
        f"\n--- Starting test: {request.node.name} ({request.node.nodeid.split('::')[0]}) ---"
    )
    yield
    # You can add post-test print statements here if needed
    # For example, to print if the test passed or failed, using request.node.rep_call.passed
    if hasattr(request.node, "rep_call"):  # Check if the call phase has a report
        if request.node.rep_call.passed:
            print(f"--- Finished test: {request.node.name} - PASSED ---")
        elif request.node.rep_call.failed:
            print(f"--- Finished test: {request.node.name} - FAILED ---")
        elif request.node.rep_call.skipped:
            print(f"--- Finished test: {request.node.name} - SKIPPED ---")
    else:
        # This might happen if the test setup failed, for example
        print(
            f"--- Finished test: {request.node.name} - (status unknown, rep_call not found) ---"
        )


# To automatically use print_test_name for all tests:
# You can create a pytest.ini or pyproject.toml and configure autouse fixtures, or
# apply it to specific test classes/modules using @pytest.mark.usefixtures("print_test_name")
# For now, we will explicitly use it in test files if needed or rely on pytest's verbose output (-v).
# The `manage_workloads` fixture is already autouse=True for session scope.
