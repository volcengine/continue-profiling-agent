# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

"""A --store_dir of more than 256 bytes keeps every save in its day directory.

The store's paths are built at their full length: a cut path would open a
directory that does not exist, and each save would land somewhere else.
"""

import os
from pathlib import Path

import pytest

from .conftest import run_command
from .cpa_utils import get_first_cpa_records_from_test_dir, run_cpa_monitor


def test_long_store_dir_holds_the_whole_run(tmp_path):
    if os.geteuid() != 0:
        pytest.skip("cpa monitor needs root")
    store = tmp_path.joinpath(*(["d" * 60] * 5))
    store.mkdir(parents=True)
    assert len(str(store)) > 300
    run_cpa_monitor(str(store), run_time=8, extra_args=["--duration", "8"])
    days = sorted(p.name for p in store.iterdir())
    assert len(days) == 1 and days[0].startswith("cpa_"), days
    day = store / days[0]
    for name in ("conf", "strmap", "idsmap", "stack.bin"):
        assert (day / name).is_file(), sorted(p.name for p in day.iterdir())
    stdout, stderr, rc = run_command(["show", "--read", str(day), "--show_range", "1"])
    assert rc == 0, stdout + stderr
    assert get_first_cpa_records_from_test_dir(str(store))
