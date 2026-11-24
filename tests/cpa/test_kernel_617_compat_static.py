# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

"""Kernel 6.15 - 6.17 changes the BPF backend follows (static checks)."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def _section(src, start, end):
    body = src[src.index(start):]
    return body[:body.index(end)]


def test_coredump_hook_follows_the_6_17_rename():
    loader = _read("bpf/src/stack_capture/stack_capture.c")
    assert 'kprobe_exists("vfs_coredump") ? "vfs_coredump" : "do_coredump"' in loader
    probe = _section(_read("bpf/src/common/capabilities_libbpf.c"), "static int probe_coredump(", "\n}\n")
    assert 'kprobe_exists("vfs_coredump")' in probe and 'kprobe_exists("do_coredump")' in probe


def test_fred_kernels_read_the_user_regs_16_bytes_lower():
    for path in ("bpf/src/stack_capture/stack_capture.c", "bpf/src/offcpu_capture/offcpu_capture.c"):
        src = _read(path)
        x86 = _section(src, "#elif defined(__CPA_BPF_ARCH_x86)", "#endif")
        assert "if (x86_fred_kernel())" in x86 and "stack_offset -= 16" in x86, path
    helper = _section(_read("bpf/src/common/trace_helpers.c"), "bool x86_fred_kernel(void)", "\n}\n")
    assert '"asm_fred_entrypoint_user"' in helper


def test_cold_parts_are_never_kprobed():
    find = _section(_read("bpf/src/common/trace_helpers.c"), "char *find_kprobe_functions(", "\n}\n")
    assert '".cold"' in find


def test_kernfs_parent_is_read_under_either_name():
    fixes = _read("bpf/src/common/include/core_fixes.bpf.h")
    parent = _section(fixes, "kernfs_node_parent(struct kernfs_node *node)", "\n}\n")
    assert "bpf_core_field_exists(n->__parent)" in parent
    assert "BPF_CORE_READ(kn, parent)" not in _read("bpf/src/target_ctl/target_ctl.bpf.c")
