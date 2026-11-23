# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

"""cpa monitor --pagefault end to end (tests/cpa/pagefault/run_pagefault_e2e.py).

One test per case of the runner, so a new case is collected without an edit
here.  A case fails on any failed check; it is skipped only when the runner
says what it could not check and why (THP unavailable or memory too
fragmented for 2 MiB pages, multi-size THP absent).  Before 5.4 every case
checks that --pagefault refuses to start, saying why.
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from .conftest import CLI_BINARY

HERE = Path(__file__).resolve().parent
RUNNER = HERE / "pagefault/run_pagefault_e2e.py"


def _cases():
    spec = importlib.util.spec_from_file_location("run_pagefault_e2e", RUNNER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return [name for name, _ in module.CASES]


@pytest.fixture(scope="module")
def pf_app(tmp_path_factory) -> Path:
    if os.geteuid() != 0:
        pytest.skip("cpa monitor --pagefault needs root")
    cc = shutil.which("gcc")
    if not cc:
        pytest.skip("gcc is required to build pf_app")
    app = tmp_path_factory.mktemp("pagefault") / "pf_app"
    # identical functions must not be folded: their stacks are the subject
    subprocess.run(
        [cc, "-O2", "-fno-ipa-icf", "-fno-omit-frame-pointer", "-pthread",
         "-Wall", "-Werror", "-o", str(app), str(HERE / "pagefault/pf_app.c")],
        check=True, timeout=120)
    return app


@pytest.mark.parametrize("case", _cases())
def test_pagefault_e2e(case: str, pf_app: Path, tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    proc = subprocess.run(
        [sys.executable, str(RUNNER), "--cpa", CLI_BINARY,
         "--app", str(pf_app), "--work", str(tmp_path / "work"),
         "--only", case, "--json", str(report)],
        capture_output=True, text=True, timeout=900)
    output = proc.stdout + proc.stderr
    results = json.loads(report.read_text()) if report.exists() else []
    assert [r["name"] for r in results] == [case], output
    result = results[0]
    assert result["ok"] and proc.returncode == 0, output
    if result["skip"]:
        pytest.skip(result["skip"])
    assert any(n.startswith("PASS ") for n in result["notes"]), output
