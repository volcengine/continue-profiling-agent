# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

"""Unit test of the sample pool and the stack sample builder."""

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


@pytest.mark.parametrize("sanitize", [False, True])
def test_stack_sample_builder_keys_samples_by_process(tmp_path: Path, sanitize: bool) -> None:
    if shutil.which("gcc") is None or platform.machine() not in ARCH:
        pytest.skip("needs gcc on x86_64 or aarch64")
    arch_dir, defines = ARCH[platform.machine()]
    gu = ROOT / "libs" / "libgunwinder" / "include"
    out = tmp_path / "test_stack_sample_builder"
    cmd = ["gcc", "-O0", "-g", "-Wall", "-Wextra", "-Werror", "-pthread", *defines,
           "-I", str(ROOT / "src" / "cpa_monitor"), "-I", str(ROOT / "src"),
           "-I", str(ROOT / "bpf" / "include"), "-I", str(gu),
           "-I", str(gu / "gunwinder"), "-I", str(gu / "arch" / arch_dir)]
    if sanitize:
        cmd += ["-fsanitize=address,undefined", "-fno-sanitize-recover=undefined"]
    cmd += ["-o", str(out), str(ROOT / "tests" / "cpa" / "test_stack_sample_builder.c"),
            str(ROOT / "src" / "cpa_monitor" / "cpa_sample_pool.c"),
            str(ROOT / "src" / "cpa_monitor" / "cpa_stack_sample_builder.c")]
    build = subprocess.run(cmd, capture_output=True, text=True)
    if sanitize and build.returncode != 0 and "sanitize" in build.stderr:
        pytest.skip("compiler without sanitizers")
    assert build.returncode == 0, build.stderr

    proc = subprocess.run([str(out)], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "stack sample builder ok" in proc.stdout
