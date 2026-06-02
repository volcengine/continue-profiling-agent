# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance


import subprocess
import os
import signal
import time
import shutil
import subprocess
import pytest
from typing import List, Dict, Optional

# Define the paths to the compiled workloads
WORKLOAD_DIR = os.path.join(os.path.dirname(__file__), "output")
SYM_C_PATH = os.path.join(WORKLOAD_DIR, "sym_c")
NO_SYM_C_PATH = os.path.join(WORKLOAD_DIR, "no_sym_c")
SYM_GO_PATH = os.path.join(WORKLOAD_DIR, "sym_go")
NO_SYM_GO_PATH = os.path.join(WORKLOAD_DIR, "no_sym_go")
RUST_WORKLOAD_PATH = os.path.join(WORKLOAD_DIR, "rust_workload")
SYM_GO_ANON_PATH = os.path.join(
    WORKLOAD_DIR, "sym_go_anon"
)  # Add path for the new workload
SYM_C_CPU0_PATH = os.path.join(
    WORKLOAD_DIR, "sym_c_cpu0"
)  # Define globally for clarity
OFFCPU_SYM_C_PATH = os.path.join(
    WORKLOAD_DIR, "offcpu_sym_c"
)  # Off-CPU C workload for probe tests

COMPILE_SCRIPT = os.path.join(os.path.dirname(__file__), "compile_workloads.sh")


def _ensure_workloads_built(required_paths: List[str]) -> None:
    os.makedirs(WORKLOAD_DIR, exist_ok=True)
    missing = [p for p in required_paths if not os.path.exists(p)]
    if not missing:
        return

    if os.path.exists(COMPILE_SCRIPT):
        subprocess.run(["bash", COMPILE_SCRIPT], check=False, text=True)

    missing = [p for p in required_paths if not os.path.exists(p)]
    if missing:
        names = ", ".join(os.path.basename(p) for p in missing)
        pytest.skip(f"Test workloads not available: {names}. Run {COMPILE_SCRIPT} to build them.")


class WorkloadManager:
    def __init__(self):
        self.processes: List[subprocess.Popen] = []
        self.workload_definitions = {
            "sym_c_test_env": lambda extra_env=None: self._start_process(
                [SYM_C_PATH],
                env=self._merge_envs({"TEST_ENV": "cpa_test"}, extra_env),
            ),
            "sym_c_cpu0": self._start_sym_c_cpu0,  # This one is special, doesn't take env directly in its definition
            "no_sym_c": lambda extra_env=None: self._start_process(
                [NO_SYM_C_PATH], env=extra_env
            ),
            "sym_c_large_stack": lambda extra_env=None: self._start_process(
                [SYM_C_PATH, "use_large_stack"], env=extra_env
            ),
            "sym_c": lambda extra_env=None: self._start_process(
                [SYM_C_PATH], env=extra_env
            ),
            "sym_go": lambda extra_env=None: self._start_process(
                [SYM_GO_PATH], env=extra_env
            ),
            "no_sym_go": lambda extra_env=None: self._start_process(
                [NO_SYM_GO_PATH], env=extra_env
            ),
            "sym_go_anon": lambda extra_env=None: self._start_process(
                [SYM_GO_ANON_PATH], env=extra_env
            ),
            "rust_workload": lambda extra_env=None: self._start_process(
                [RUST_WORKLOAD_PATH], env=extra_env
            ),
            "offcpu_sym_c": lambda extra_env=None: self._start_process(
                [OFFCPU_SYM_C_PATH], env=extra_env
            ),
            # Add the new workload definition for the env test
            "sym_c_pod_env_test": lambda extra_env=None: self._start_process(
                [SYM_C_PATH], env=extra_env
            ),
        }
        self._sym_c_cpu0_prepared = False

    def _merge_envs(
        self, base_env: Optional[Dict[str, str]], override_env: Optional[Dict[str, str]]
    ) -> Optional[Dict[str, str]]:
        if base_env is None and override_env is None:
            return None
        merged_env = base_env.copy() if base_env else {}
        if override_env:
            merged_env.update(override_env)
        return merged_env

    def _start_process(
        self,
        command: List[str],
        env: Optional[Dict[str, str]] = None,
        use_shell: bool = False,
        cwd: Optional[str] = None,
    ) -> Optional[subprocess.Popen]:
        print(f"Starting: {' '.join(command)}")
        process_env = os.environ.copy()
        if env:
            process_env.update(env)

        print(f"Environment for process: {process_env}")
        try:
            # Redirect stdout and stderr to /dev/null to suppress output
            with open(os.devnull, "w") as devnull:
                p = subprocess.Popen(
                    command,
                    shell=use_shell,
                    env=process_env,
                    cwd=cwd,
                    preexec_fn=os.setsid,
                    stdout=devnull,
                    stderr=devnull,
                )
            self.processes.append(p)
            # print(f"Started PID: {p.pid} - {' '.join(command)}") # Suppress this print
            return p
        except FileNotFoundError:
            # print(f"Error: Workload executable not found at {command[0]}") # Suppress this print
            return None
        except Exception as e:
            # print(f"Error starting workload {' '.join(command)}: {e}") # Suppress this print
            return None

    def _prepare_sym_c_cpu0(self):
        if not self._sym_c_cpu0_prepared:
            try:
                if not os.path.exists(SYM_C_PATH):
                    print(
                        f"Error: Base workload {SYM_C_PATH} not found for sym_c_cpu0 setup."
                    )
                    return False
                shutil.copy(SYM_C_PATH, SYM_C_CPU0_PATH)
                os.chmod(SYM_C_CPU0_PATH, 0o755)
                print(f"Copied {SYM_C_PATH} to {SYM_C_CPU0_PATH} for CPU 0 binding.")
                self._sym_c_cpu0_prepared = True
                return True
            except Exception as e:
                print(f"Error setting up sym_c_cpu0: {e}")
                return False
        return True

    def _start_sym_c_cpu0(self) -> Optional[subprocess.Popen]:
        if not self._prepare_sym_c_cpu0():
            return None
        return self._start_process(["taskset", "-c", "0", SYM_C_CPU0_PATH])

    def run_selected_workloads(
        self,
        workload_names: List[str],
        custom_envs_for_workloads: Optional[Dict[str, Dict[str, str]]] = None,
    ):
        # print(f"Attempting to run selected workloads: {workload_names}") # Suppress this print
        for name in workload_names:
            if name in self.workload_definitions:
                print(f"Running workload: {name}")  # Suppress this print
                start_func = self.workload_definitions[name]
                current_custom_env = (
                    custom_envs_for_workloads.get(name)
                    if custom_envs_for_workloads
                    else None
                )

                if (
                    name == "sym_c_cpu0"
                ):  # Special case for methods not defined as simple lambdas taking env
                    if current_custom_env:
                        # This is tricky. _start_sym_c_cpu0 calls _start_process internally.
                        # We'd need to modify _start_sym_c_cpu0 to accept an env or handle it here.
                        # For now, let's assume sym_c_cpu0 won't have custom envs in this manner for simplicity.
                        # Or, _start_sym_c_cpu0 could be changed to: self._start_process(["taskset", "-c", "0", SYM_C_CPU0_PATH], env=extra_env)
                        # And its definition in workload_definitions becomes a lambda too.
                        # For now, we'll skip passing env to _start_sym_c_cpu0 if it's not a lambda that accepts it.
                        print(
                            f"Warning: Custom environment for '{name}' is provided but not directly supported by its current start mechanism. It will be ignored."
                        )
                        start_func()  # Call without env
                    else:
                        start_func()
                else:
                    try:
                        start_func(extra_env=current_custom_env)
                    except TypeError as e:
                        # This might happen if a definition was missed or is not a lambda expecting extra_env
                        print(
                            f"Warning: Could not pass 'extra_env' to workload '{name}'. Starting with default env. Error: {e}"
                        )
                        start_func()  # Fallback to calling without env
            else:
                print(f"Warning: Workload '{name}' not defined.")  # Keep this warning
        # print("Finished attempting to run selected workloads.") # Suppress this print

    def terminate_all_workloads(self):
        # print('Stopping all managed workloads...') # Suppress this print
        for p in self.processes:
            if p.poll() is None:  # Check if process is still running
                pgid = 0
                try:
                    pgid = os.getpgid(p.pid)
                    print(f"Stopping process group {pgid} (PID: {p.pid})...")
                    os.killpg(pgid, signal.SIGTERM)
                except ProcessLookupError:
                    print(
                        f"Process group for PID {p.pid} (expected pgid {pgid if pgid else 'N/A'}) already terminated."
                    )
                except Exception as e:
                    print(
                        f"Error stopping process group for PID {p.pid} (expected pgid {pgid if pgid else 'N/A'}): {e}"
                    )

        # Wait for processes to terminate
        terminated_processes = []
        for p in self.processes:
            try:
                p.wait(timeout=5)  # Wait up to 5 seconds
                terminated_processes.append(p)
            except subprocess.TimeoutExpired:
                pgid = 0
                try:
                    pgid = os.getpgid(p.pid)
                    print(
                        f"Process PID {p.pid} (group {pgid}) did not terminate, killing..."
                    )
                    os.killpg(pgid, signal.SIGKILL)  # Force kill if still running
                    p.wait()
                    terminated_processes.append(p)
                except Exception as e:
                    print(
                        f"Error force killing process group for PID {p.pid} (expected pgid {pgid if pgid else 'N/A'}): {e}"
                    )
            except Exception as e:
                print(f"Error during process wait for PID {p.pid}: {e}")
                # If wait fails for other reasons, consider it terminated or problematic
                terminated_processes.append(p)

        # Update the list of processes
        self.processes = [p for p in self.processes if p not in terminated_processes]
        print("All managed workloads stopped.")


# Global instance for signal handling if script is run directly
_global_workload_manager: Optional[WorkloadManager] = None


def global_signal_handler(sig, frame):
    if _global_workload_manager:
        _global_workload_manager.terminate_all_workloads()
    exit(0)


# Functions to be called from test cases
def run_workloads(
    workload_names: List[str],
    custom_env_for_workload: Optional[Dict[str, Dict[str, str]]] = None,
) -> WorkloadManager:
    required = []
    for name in workload_names:
        if name in ("sym_c", "sym_c_large_stack", "sym_c_test_env", "sym_c_pod_env_test", "sym_c_cpu0"):
            required.append(SYM_C_PATH)
        elif name == "no_sym_c":
            required.append(NO_SYM_C_PATH)
        elif name == "sym_go":
            required.append(SYM_GO_PATH)
        elif name == "no_sym_go":
            required.append(NO_SYM_GO_PATH)
        elif name == "sym_go_anon":
            required.append(SYM_GO_ANON_PATH)
        elif name == "rust_workload":
            required.append(RUST_WORKLOAD_PATH)
        elif name == "offcpu_sym_c":
            required.append(OFFCPU_SYM_C_PATH)
    _ensure_workloads_built(required)

    manager = WorkloadManager()
    manager.run_selected_workloads(
        workload_names, custom_envs_for_workloads=custom_env_for_workload
    )
    return manager


def terminate_workloads(manager: WorkloadManager):
    if manager:
        manager.terminate_all_workloads()


if __name__ == "__main__":
    _global_workload_manager = WorkloadManager()
    signal.signal(signal.SIGINT, global_signal_handler)
    signal.signal(signal.SIGTERM, global_signal_handler)

    print(f"Looking for workloads in: {WORKLOAD_DIR}")

    all_workloads = [
        "sym_c_test_env",
        "sym_c_cpu0",
        "no_sym_c",
        "sym_c_large_stack",
        "sym_go",
        "no_sym_go",
        "rust",
    ]
    _global_workload_manager.run_selected_workloads(all_workloads)

    print("All workloads started. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
            active_processes = False
            for p in _global_workload_manager.processes[
                :
            ]:  # Iterate over a copy for safe removal
                if p.poll() is not None:
                    print(
                        f"Workload PID {p.pid} has terminated with exit code {p.returncode}."
                    )
                    _global_workload_manager.processes.remove(p)
                else:
                    active_processes = True
            if not active_processes:
                print("All workloads have finished.")
                break
    except KeyboardInterrupt:
        print("Main loop interrupted by Ctrl+C.")
    except Exception as e:
        print(f"Main loop interrupted: {e}")
    finally:
        print("Performing final cleanup from __main__...")
        if _global_workload_manager:
            _global_workload_manager.terminate_all_workloads()
