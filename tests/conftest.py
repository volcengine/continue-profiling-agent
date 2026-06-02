# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance


from __future__ import annotations

import os
import shutil
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parents[1]
_TEST_TMP_ROOT = _REPO_ROOT / ".test-tmp"
_RUNTIME_DIR = _TEST_TMP_ROOT / "runtime"


def pytest_sessionstart(session) -> None:
    _TEST_TMP_ROOT.mkdir(parents=True, exist_ok=True)
    if _RUNTIME_DIR.exists():
        shutil.rmtree(_RUNTIME_DIR)
    _RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    os.environ["CPA_TEST_TMP_DIR"] = str(_RUNTIME_DIR)
