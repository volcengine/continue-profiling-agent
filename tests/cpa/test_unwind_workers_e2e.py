# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

"""--unwind_workers: several unwind threads, each process unwound by one.

The whole suite can also run with several workers through
tests/cpa/tools/cpa_unwind_workers.sh (see docs/en/testing.md).
"""

import shutil
import subprocess
import time
from pathlib import Path

import pytest

from .conftest import run_command
from .cpa_utils import get_first_cpa_records_from_test_dir, run_cpa_monitor


def _spin(tmp_path: Path, name: str) -> subprocess.Popen:
    path = tmp_path / name
    shutil.copy("/usr/bin/yes", path)
    return subprocess.Popen([str(path)], stdout=subprocess.DEVNULL)


@pytest.mark.parametrize("value", ["0", "x", "1x", "65", "99999999999"])
def test_bad_unwind_workers_is_refused(tmp_path, value):
    stdout, stderr, rc = run_command(
        ["monitor", "--store_dir", str(tmp_path), "--duration=1", f"--unwind_workers={value}"])
    out = stdout + stderr
    assert rc != 0, out
    assert "--unwind_workers must be an integer from 1 to" in out, out
    # refused before any worker started
    assert "Init SUCCESS workers" not in out, out


@pytest.mark.parametrize("workers", [1, 4])
def test_every_process_is_unwound(tmp_path, pytestconfig, workers):
    """Processes hashed to different workers all get user stacks."""
    names = [f"uw{i}" for i in range(8)]
    procs = [_spin(tmp_path, n) for n in names]
    store = tmp_path / "store"
    store.mkdir()
    try:
        time.sleep(0.5)
        # 4.14 spends up to 8 s starting (BTF, lite objects): sample well past it
        run_cpa_monitor(str(store), run_time=15,
                        extra_args=[f"--unwind_workers={workers}", "--duration", "15",
                                    "--comm=" + ",".join(names)])
        records = get_first_cpa_records_from_test_dir(str(store), pytestconfig)
    finally:
        for p in procs:
            p.kill()
            p.wait(timeout=5)
    by_pid = {}
    for r in records:
        by_pid.setdefault(r.pid, []).append(r)
    assert set(by_pid) == {p.pid for p in procs}, sorted(by_pid)
    for pid, recs in by_pid.items():
        # a user frame below the metadata: the process was unwound
        user = [f for r in recs for f in r.stack if "_[k]" not in f and not f.startswith("<#")]
        assert user, (pid, [r.stack for r in recs][:3])
