# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

"""End-to-end process selection: who is sampled for each selection option.

Every case starts busy loops under distinct names (copies of `yes`), runs
`cpa monitor` with one selection and checks which of them show up in the
store.  Needs root and the BPF backend.
"""

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from .conftest import run_command
from .cpa_utils import get_first_cpa_records_from_test_dir, run_cpa_monitor


def _spinner(tmp_path: Path, name: str) -> Path:
    path = tmp_path / name
    shutil.copy("/usr/bin/yes", path)
    return path


def _start(path: Path) -> subprocess.Popen:
    return subprocess.Popen([str(path)], stdout=subprocess.DEVNULL)


def _stop(*procs: subprocess.Popen) -> None:
    for proc in procs:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)


def _sampled(store: Path, pytestconfig) -> dict:
    """pid -> sample count, by process name, of what the store holds."""
    seen: dict = {}
    for record in get_first_cpa_records_from_test_dir(str(store), pytestconfig):
        key = (record.process_name, str(record.pid))
        seen[key] = seen.get(key, 0) + int(record.samples)
    return seen


def _pids_of(seen: dict, name: str) -> set:
    return {int(pid) for (proc, pid) in seen if proc == name}


def _monitor(store: Path, args: list, run_time: int = 5) -> None:
    store.mkdir(parents=True, exist_ok=True)
    run_cpa_monitor(str(store), run_time=run_time,
                    extra_args=[*args, "--duration", str(run_time)])


def test_comm_selects_by_process_name(tmp_path, pytestconfig):
    a, b = _start(_spinner(tmp_path, "selA")), _start(_spinner(tmp_path, "selB"))
    try:
        time.sleep(0.5)
        _monitor(tmp_path / "store", ["--comm=selA"])
        seen = _sampled(tmp_path / "store", pytestconfig)
    finally:
        _stop(a, b)
    assert _pids_of(seen, "selA") == {a.pid}, seen
    assert not _pids_of(seen, "selB"), seen


def test_pid_list_selects_each_process(tmp_path, pytestconfig):
    a, b = _start(_spinner(tmp_path, "selA")), _start(_spinner(tmp_path, "selB"))
    c = _start(_spinner(tmp_path, "selC"))
    try:
        time.sleep(0.5)
        _monitor(tmp_path / "store", [f"--pid={a.pid},{b.pid}"])
        seen = _sampled(tmp_path / "store", pytestconfig)
    finally:
        _stop(a, b, c)
    assert _pids_of(seen, "selA") == {a.pid} and _pids_of(seen, "selB") == {b.pid}, seen
    assert not _pids_of(seen, "selC"), seen


def test_exe_selects_by_executable(tmp_path, pytestconfig):
    exe_a = _spinner(tmp_path, "selA")
    a, b = _start(exe_a), _start(_spinner(tmp_path, "selB"))
    try:
        time.sleep(0.5)
        _monitor(tmp_path / "store", [f"--exe={exe_a}"])
        seen = _sampled(tmp_path / "store", pytestconfig)
    finally:
        _stop(a, b)
    assert _pids_of(seen, "selA") == {a.pid}, seen
    assert not _pids_of(seen, "selB"), seen


def test_new_only_skips_running_processes(tmp_path, pytestconfig):
    exe = _spinner(tmp_path, "selN")
    old = _start(exe)
    store = tmp_path / "store"
    store.mkdir()
    late = None
    try:
        time.sleep(0.5)
        monitor = subprocess.Popen(
            [os.environ.get("TEST_CPA_PATH", "./build/bin/cpa"), "monitor",
             "--store_dir", str(store), "--comm=selN", "--new_only",
             "--duration", "6"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        late = _start(exe)
        assert monitor.wait(timeout=30) == 0
        seen = _sampled(store, pytestconfig)
    finally:
        _stop(old, *(p for p in [late] if p))
    assert _pids_of(seen, "selN") == {late.pid}, seen


def test_children_follow_the_selected_process(tmp_path, pytestconfig):
    spinner = _spinner(tmp_path, "selKid")
    parent = subprocess.Popen(
        ["/bin/sh", "-c", f"sleep 1.5; {spinner} > /dev/null & wait"])
    other = _start(_spinner(tmp_path, "selOther"))
    try:
        _monitor(tmp_path / "store", [f"--pid={parent.pid}", "--children"])
        seen = _sampled(tmp_path / "store", pytestconfig)
    finally:
        subprocess.run(["pkill", "-f", str(spinner)], check=False)
        _stop(parent, other)
    assert _pids_of(seen, "selKid"), seen
    assert not _pids_of(seen, "selOther"), seen


def test_first_match_samples_one_process_and_stops(tmp_path, pytestconfig):
    exe = _spinner(tmp_path, "selF")
    store = tmp_path / "store"
    store.mkdir()
    procs = []
    try:
        monitor = subprocess.Popen(
            [os.environ.get("TEST_CPA_PATH", "./build/bin/cpa"), "monitor",
             "--store_dir", str(store), "--comm=selF", "--first_match",
             "--duration", "30"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        time.sleep(1.5)
        procs = [_start(exe), _start(exe)]
        time.sleep(2)
        _stop(procs[0])
        _stop(procs[1])
        # the run ends by itself once its one process is gone
        out, _ = monitor.communicate(timeout=25)
        assert monitor.returncode == 0, out
        assert "first_match finished" in out, out
        seen = _sampled(store, pytestconfig)
    finally:
        _stop(*procs)
    assert len(_pids_of(seen, "selF")) == 1, seen


def test_startup_window_stops_sampling_a_process(tmp_path, pytestconfig):
    a = _start(_spinner(tmp_path, "selW"))
    try:
        time.sleep(0.5)
        _monitor(tmp_path / "store", ["--comm=selW", "--startup_window=1"], run_time=6)
        seen = _sampled(tmp_path / "store", pytestconfig)
    finally:
        _stop(a)
    samples = sum(n for (proc, _), n in seen.items() if proc == "selW")
    # about 1 s of a 6 s run at 49 Hz, with room for timing
    assert 10 <= samples <= 120, seen


@pytest.mark.parametrize(
    "args,message",
    [
        (["--pid=1,2", "--comm=x"], "cannot be combined"),
        (["--new_only"], "needs at least one of"),
        (["--cgroup_recursive"], "requires --cgroup"),
        (["--container_pid=1", "--cgroup=/x"], "already selects a cgroup"),
        (["--comm=averyveryverylongname"], "longer than 15 bytes"),
        (["--exe=relative"], "must be an absolute path"),
        (["--thread_comm=a", "--comm=b"], "only be combined with a single --pid"),
        (["--startup_window=5"], "needs a rule based selection"),
        (["--cgroup=/cpa-no-such-cgroup"], "cannot read the id"),
    ],
)
def test_bad_selection_is_refused(tmp_path, args, message):
    stdout, stderr, rc = run_command(
        ["monitor", "--store_dir", str(tmp_path), "--duration=1", *args])
    out = stdout + stderr
    assert rc != 0, out
    assert message in out, out
