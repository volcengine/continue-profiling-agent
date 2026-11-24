# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

"""The kernel capability model and `cpa capabilities`."""

import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

from .conftest import run_command

REPO_ROOT = Path(__file__).resolve().parents[2]
CAPABILITIES_C = REPO_ROOT / "bpf/src/common/capabilities.c"
BPF_INCLUDE = REPO_ROOT / "bpf/include"

CAPABILITIES = [
    "get_stack_perf_event",
    "get_stack_kprobe",
    "get_stack_tracepoint",
    "perf_event_program_load",
    "kprobe_program_load",
    "tracepoint_program_load",
    "process_exit",
    "coredump",
    "ringbuf",
    "pagefault",
    "find_vma",
]

HARNESS = r"""
#include <cpa_bpf/capabilities.h>

#include <errno.h>
#include <stdio.h>

static int probe_calls[CPA_CAP_COUNT];

static int fake_probe(enum cpa_capability_id id, void *ctx)
{
    (void)ctx;
    probe_calls[id]++;
    switch (id) {
    case CPA_CAP_GET_STACK_PERF_EVENT:
        return 1;
    case CPA_CAP_GET_STACK_KPROBE:
        return 0;
    case CPA_CAP_GET_STACK_TRACEPOINT:
        return -EACCES;
    case CPA_CAP_RINGBUF:
        return -EIO;
    default:
        return 1;
    }
}

static int expect(const struct cpa_capability_set *set, enum cpa_capability_id id,
                  enum cpa_capability_state state, enum cpa_capability_reason reason,
                  int error_code)
{
    const struct cpa_capability_result *r = cpa_capabilities_result(set, id);

    if (!r || r->state != state || r->reason != reason || r->error_code != error_code) {
        fprintf(stderr, "unexpected result for id %d\n", id);
        return 1;
    }
    return !cpa_capability_id_name(id) || !cpa_capability_state_name(state) ||
           !cpa_capability_reason_name(reason);
}

int main(void)
{
    struct cpa_capability_detector detector = { 0 };
    const struct cpa_capability_probe_ops ops = { .probe = fake_probe };
    const struct cpa_capability_set *first, *second;
    int i;

    first = cpa_capabilities_detect_once(&detector, &ops, NULL);
    second = cpa_capabilities_detect_once(&detector, &ops, NULL);
    if (!first || first != second)
        return 10;
    for (i = 0; i < CPA_CAP_COUNT; i++)
        if (probe_calls[i] != 1)
            return 11;
    if (expect(first, CPA_CAP_GET_STACK_PERF_EVENT, CPA_CAP_SUPPORTED,
               CPA_CAP_REASON_PROBE_SUCCEEDED, 0))
        return 20;
    if (expect(first, CPA_CAP_GET_STACK_KPROBE, CPA_CAP_UNSUPPORTED,
               CPA_CAP_REASON_KERNEL_UNSUPPORTED, 0))
        return 21;
    if (expect(first, CPA_CAP_GET_STACK_TRACEPOINT, CPA_CAP_UNAVAILABLE,
               CPA_CAP_REASON_PERMISSION_DENIED, EACCES))
        return 22;
    if (expect(first, CPA_CAP_RINGBUF, CPA_CAP_PROBE_ERROR,
               CPA_CAP_REASON_PROBE_FAILED, EIO))
        return 23;
    if (!cpa_capability_supported(first, CPA_CAP_GET_STACK_PERF_EVENT) ||
        cpa_capability_supported(first, CPA_CAP_GET_STACK_KPROBE) ||
        cpa_capability_supported(first, CPA_CAP_COUNT) ||
        cpa_capabilities_result(first, CPA_CAP_COUNT) ||
        cpa_capability_id_name(CPA_CAP_COUNT))
        return 30;
    return 0;
}
"""


def test_detection_is_cached_and_keeps_the_reason(tmp_path: Path) -> None:
    cc = shutil.which("gcc") or shutil.which("cc")
    if not cc:
        pytest.skip("a C compiler is needed for the capability model test")
    source = tmp_path / "model.c"
    binary = tmp_path / "model"
    source.write_text(textwrap.dedent(HARNESS).lstrip(), encoding="utf-8")
    subprocess.run(
        [cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-I", str(BPF_INCLUDE),
         str(source), str(CAPABILITIES_C), "-o", str(binary)],
        check=True, timeout=60,
    )
    result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr


def test_capabilities_command_prints_every_capability() -> None:
    stdout, stderr, rc = run_command(["capabilities"])
    assert rc == 0, stdout + stderr
    lines = dict(line.split(": ", 1) for line in stdout.splitlines() if ": " in line)
    assert lines["schema_version"] == "1"
    assert lines["kernel.release"] and lines["kernel.machine"]
    for name in CAPABILITIES:
        assert lines[f"capability.{name}.state"] in {
            "supported", "unsupported", "unavailable", "probe_error"}, stdout
        assert lines[f"capability.{name}.reason"] in {
            "probe_succeeded", "kernel_unsupported", "permission_denied", "probe_failed"}, stdout
        assert int(lines[f"capability.{name}.error_code"]) >= 0
    listed = {key.split(".")[1] for key in lines if key.startswith("capability.")}
    assert listed == set(CAPABILITIES), stdout
