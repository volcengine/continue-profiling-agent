# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

"""Unit test of the unwind queue lanes and the per-sample frame buffer."""

import platform
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
ARCH = {
    "x86_64": ("x86", ["-DGUNWINDER_X86", "-D__CPA_BPF_ARCH_x86"]),
    "aarch64": ("arm64", ["-DGUNWINDER_ARM64", "-D__CPA_BPF_ARCH_arm64"]),
}


@pytest.mark.parametrize("sanitize", ["", "address,undefined", "thread"])
def test_unwind_queue(tmp_path: Path, sanitize: str) -> None:
    if shutil.which("gcc") is None or platform.machine() not in ARCH:
        pytest.skip("needs gcc on x86_64 or aarch64")
    arch_dir, defines = ARCH[platform.machine()]
    gu = ROOT / "libs" / "libgunwinder" / "include"
    mon = ROOT / "src" / "cpa_monitor"
    out = tmp_path / "test_unwind_queue"
    # cli.h includes the build's generated subcommand list: none needed here
    (tmp_path / "auto").mkdir()
    (tmp_path / "auto" / "gen_modules.h").write_text("")
    cmd = ["gcc", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-pthread", *defines,
           "-I", str(tmp_path), "-I", str(mon), "-I", str(ROOT / "src"),
           *[arg for d in sorted((ROOT / "src").iterdir()) if d.is_dir()
             for arg in ("-I", str(d))],
           # libbpf's headers as the build installs them: no system libbpf needed
           "-I", str(ROOT / "build" / "libs" / "libbpf" / "include"),
           "-I", str(ROOT / "bpf" / "src" / "common" / "include"),
           "-I", str(ROOT / "bpf" / "include"), "-I", str(gu),
           "-I", str(gu / "gunwinder"), "-I", str(gu / "arch" / arch_dir)]
    if sanitize:
        cmd += [f"-fsanitize={sanitize}"]
        if "undefined" in sanitize:
            cmd += ["-fno-sanitize-recover=undefined"]
    cmd += ["-o", str(out), str(ROOT / "tests" / "cpa" / "test_unwind_queue.c"),
            str(mon / "cpa_unwind_queue.c"), str(mon / "cpa_frames.c"),
            str(mon / "cpa_sample_pool.c"), str(mon / "cpa_drop_policy.c"),
            str(ROOT / "src" / "cli_queue_helper" / "cli_single_queue.c")]
    build = subprocess.run(cmd, capture_output=True, text=True)
    if sanitize and build.returncode != 0 and "sanitize" in build.stderr:
        pytest.skip("compiler without this sanitizer")
    assert build.returncode == 0, build.stderr

    env = {"TSAN_OPTIONS": "halt_on_error=1", "ASAN_OPTIONS": "detect_leaks=1"}
    proc = subprocess.run([str(out)], capture_output=True, text=True, timeout=300, env=env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "unwind queue ok" in proc.stdout
