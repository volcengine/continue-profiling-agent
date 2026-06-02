# SPDX-License-Identifier: BSD-2-Clause
# SPDX-FileCopyrightText: ByteDance Inc

import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_stackmap_timewheel_buffers_and_clamps_late_samples() -> None:
    sources = [
        ROOT / "tests" / "cpa" / "test_stackmap_timewheel.c",
        ROOT / "src" / "cli_stackmap_helper" / "stackmap_timewheel.c",
        ROOT / "src" / "cli_stackmap_helper" / "stackmap_count_table.c",
    ]

    with tempfile.TemporaryDirectory(prefix="cpa_stackmap_timewheel_") as td:
        out_bin = Path(td) / "test_stackmap_timewheel"
        cmd = [
            "gcc",
            "-O0",
            "-g",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(ROOT / "src" / "cli_stackmap_helper"),
            "-o",
            str(out_bin),
        ]
        cmd.extend(str(source) for source in sources)
        subprocess.check_call(cmd)

        proc = subprocess.run([str(out_bin)], capture_output=True, text=True)
        assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr
