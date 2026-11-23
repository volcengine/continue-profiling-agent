# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

"""cpa monitor --enable_exit_capture end to end (tests/cpa/exit_capture/run_exit_e2e.py)."""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from .conftest import CLI_BINARY

HERE = Path(__file__).resolve().parent


@pytest.mark.parametrize("unwind_workers", [1, 4])
def test_exit_capture_e2e(tmp_path: Path, unwind_workers: int) -> None:
    if os.geteuid() != 0:
        pytest.skip("exit capture e2e requires root/BPF privileges")
    cc = shutil.which("gcc")
    if not cc:
        pytest.skip("gcc is required for exit capture e2e")
    app = tmp_path / "exit_app"
    subprocess.run(
        [cc, "-O0", "-g", "-fno-omit-frame-pointer", "-pthread",
         str(HERE / "exit_capture/exit_app.c"), "-o", str(app)],
        check=True, timeout=60)
    proc = subprocess.run(
        [sys.executable, str(HERE / "exit_capture/run_exit_e2e.py"),
         "--cpa", CLI_BINARY, "--app", str(app), "--work", str(tmp_path / "work"),
         "--unwind_workers", str(unwind_workers)],
        capture_output=True, text=True, timeout=900)
    output = proc.stdout + proc.stderr
    # as root a refused init is a failure, not a missing privilege
    assert proc.returncode == 0, output
    # every case ran and passed
    assert re.search(r"^SUMMARY: (\d+)/\1 passed$", output, re.M), output
    assert "[FAIL]" not in output, output
