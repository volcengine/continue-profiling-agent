# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

"""cpa monitor --pagefault: tracker unit tests and static contracts."""

import importlib.util
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BPF_SRC = "bpf/src/stack_capture/stack_capture.bpf.c"
LOADER = "bpf/src/stack_capture/stack_capture.c"
PROBES = "bpf/src/common/capabilities_libbpf.c"
GLUE = "src/cpa_monitor/cpa_pagefault.c"
CAPTURE = "src/cpa_monitor/cpa_bpf_capture.c"


def _read(path: str) -> str:
    return (REPO_ROOT / path).read_text(encoding="utf-8")


def _section(src: str, start: str, end: str) -> str:
    body = src[src.index(start):]
    return body[:body.index(end)]


def _e2e():
    spec = importlib.util.spec_from_file_location(
        "run_pagefault_e2e", REPO_ROOT / "tests/cpa/pagefault/run_pagefault_e2e.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_tracker_and_sampling(tmp_path: Path) -> None:
    if shutil.which("gcc") is None:
        pytest.skip("needs gcc")
    binary = tmp_path / "tracker_harness"
    subprocess.run(
        ["gcc", "-Wall", "-Werror", "-O2",
         "-I", str(REPO_ROOT / "bpf/include"),
         "-I", str(REPO_ROOT / "src/cpa_monitor"),
         "-I", str(REPO_ROOT / "src"),
         "-o", str(binary),
         str(REPO_ROOT / "tests/cpa/pagefault/tracker_harness.c"),
         str(REPO_ROOT / "src/cpa_monitor/cpa_pagefault_tracker.c"),
         "-lm"],
        check=True)
    result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "FAIL" not in result.stdout
    # every check ran: a harness that stops early must not pass
    src = _read("tests/cpa/pagefault/tracker_harness.c")
    checks = src.count("\tCHECK(")
    passed = result.stdout.count("PASS ")
    assert checks >= 30 and passed == checks, (checks, result.stdout)
    assert "failures=0" in result.stdout


def test_judge_takes_only_anonymous_pages_of_the_target() -> None:
    src = _read(BPF_SRC)
    anon = _section(src, "static __always_inline struct pf_config *pf_target_anon(", "\n}\n")
    # its own address space, then vma_is_anonymous(), the pre-4.18 guard,
    # and no shared mapping
    for cond in ("BPF_CORE_READ(vma, vm_mm) != mm", "BPF_CORE_READ(vma, vm_ops)",
                 "BPF_CORE_READ(vma, vm_file)", "PF_VM_SHARED"):
        assert cond in anon, cond
    sample = _section(src, "static __always_inline int pf_sample_new(", "\n}\n")
    assert "pf_pages_sampled(addr, pages" in sample
    assert "pf_pages_weight(pages" in sample
    assert "bpf_tail_call(ctx, &pf_progs, 0)" in sample
    # both entries judge the vma before anything is sampled
    for entry in ("int pf_new_anon_page(", "int pf_new_anon_folio("):
        body = _section(src, entry, "\n}\n")
        assert body.index("pf_target_anon(vma)") < body.index("pf_sample_new(")
    # 5.4 - 5.18: a compound page is a THP, always in the sample
    assert "compound ? PF_THP_PAGES : 1" in _section(src, "int pf_new_anon_page(", "\n}\n")
    assert "#define PF_SAMPLE_PAGES_MAX PF_THP_PAGES" in _read("bpf/include/cpa_bpf/pagefault_sample.h")


def test_folio_entry_reads_the_size_through_btf() -> None:
    """6.3+: the folio's order, by its PG_head bit (whose number differs
    between versions) and _folio_order (6.1 - 6.5) or _flags_1 (6.6+); an
    order beyond a PMD's is counted as an unknown size, not recorded."""
    src = _read(BPF_SRC)
    assert 'SEC("kprobe/folio_add_new_anon_rmap")' in src
    folio = _section(src, "int pf_new_anon_folio(", "\n}\n")
    assert "bpf_core_enum_value(enum pageflags, PG_head)" in folio
    assert "bpf_core_field_exists(folio->_folio_order)" in folio
    assert "_flags_1) & 0xff" in folio
    bad = _section(folio, "if (order > PF_THP_ORDER) {", "}")
    assert "unknown_folios" in bad and "return 0;" in folio[folio.index(bad):]
    assert "1U << order" in folio
    # a struct the compile headers may lack: a local CO-RE stand-in
    assert "preserve_access_index" in _section(src, "struct folio___pf {", ";\n\n")
    # userspace reports it as INCOMPLETE
    mon = _read(GLUE)
    assert "now.unknown_folios = bpf.unknown_folios;" in mon
    assert "new pages of an unknown size" in mon


def test_one_entry_is_chosen_in_one_place() -> None:
    """With folio_add_new_anon_rmap present only it is attached (the page
    function of 6.3 - 6.7 wraps it: both would count twice); else the
    four-argument page_add_new_anon_rmap; else a refusal saying why."""
    probes = _read(PROBES)
    decide = _section(probes, "static void pagefault_rmap_decide(", "\n}\n")
    assert decide.index('"folio_add_new_anon_rmap"') < decide.index('"page_add_new_anon_rmap"')
    assert "btf_vlen(proto) == 4" in decide
    assert "KERNEL_VERSION(5, 19, 0)" in decide
    assert "pagefault_folio_layout(vmlinux)" in decide
    assert "CONFIG_DEBUG_INFO_BTF" in decide
    # a kernel without BTF fails the load with ESRCH, read before any other call
    load = decide.index("btf__load_vmlinux_btf()")
    assert decide.index("err = errno;") == decide.index("\n", load) + 2
    layout = _section(probes, "static const char *pagefault_folio_layout(", "\n}\n")
    for need in ('"PG_head"', '"flags"', '"_folio_order"', '"_flags_1"'):
        assert need in layout, need
    # the capability is derived from the decision, not judged again
    assert "cpa_pagefault_rmap()" in _section(probes, "static int probe_pagefault(", "\n}\n")
    assert "return probe_pagefault();" in _section(probes, "case CPA_CAP_PAGEFAULT:", "\n\tcase ")
    loader = _read(LOADER)
    load_fn = _section(loader, "static int load_pagefault(", "\n}\n")
    assert "bpf_program__set_autoload(pf_obj->progs.pf_new_anon_page, !folio)" in load_fn
    assert "bpf_program__set_autoload(pf_obj->progs.pf_new_anon_folio, folio)" in load_fn
    attach = _section(loader, "static int attach_pagefault(", "\n}\n")
    assert "cpa_pagefault_rmap()" in attach
    assert "pf_obj->progs.pf_new_anon_folio" in attach and "pf_obj->progs.pf_new_anon_page" in attach
    # the start log names the entry and flags a series never run
    assert "new anonymous pages from %s" in attach
    assert "rmap->unverified" in attach
    assert "has not been verified" in decide
    assert '#define PF_VERIFIED_FOLIO_KERNELS "6.6, 6.8"' in probes


def test_a_fixed_target_skips_other_processes_syscall_exits() -> None:
    """With a fixed --pid another process' call was never remembered, so
    the tgid is compared before the pf_pending hash lookup."""
    src = _read(BPF_SRC)
    gate = _section(src, "static __always_inline bool pf_exit(", "\n}\n")
    check = "cfg->tgid && cfg->tgid != (u32)(pid_tgid >> 32)"
    assert check in gate
    assert gate.index(check) < gate.index("bpf_map_lookup_elem(&pf_pending")
    # exit_mmap keeps its pf_mm lookup first: the last user of the mm may
    # be another process
    mm_gone = _section(src, "int pf_mm_gone(", "\n}\n")
    assert mm_gone.index("bpf_map_lookup_elem(&pf_mm") < mm_gone.index("pf_target_config()")


def test_kernels_before_5_4_are_refused_with_the_reason() -> None:
    """Before 5.4 a full perf buffer drops a sampled page without the BPF
    program seeing it: the live set could be short with no INCOMPLETE.  The
    decision refuses those kernels first, and the configuration refuses
    with its reason before anything is set up; the e2e expects it there."""
    decide = _section(_read(PROBES), "static void pagefault_rmap_decide(", "\n}\n")
    check = "get_kernel_version() < KERNEL_VERSION(5, 4, 0)"
    assert decide.index(check) < decide.index("find_ksyms_addr(")
    refusal = decide[decide.index(check):]
    refusal = refusal[:refusal.index("return;")]
    message = "".join(re.findall(r'"([^"]*)"', refusal))
    e2e = _e2e()
    assert e2e.TOO_OLD in message, message
    body = _section(_read(GLUE), "int cpa_pagefault_configure(", "\n}\n")
    assert body.index("if (!pf.enabled)") < body.index("rmap->entry == CPA_PF_ENTRY_NONE") < \
        body.index("pf_sample_pages")
    assert e2e.kernel_before_5_4("4.14.81.bm.22-amd64")
    assert e2e.kernel_before_5_4("4.19.117-amd64")
    assert not e2e.kernel_before_5_4("5.4.56-amd64")
    assert not e2e.kernel_before_5_4("5.15.152-amd64")


def test_every_release_path_is_hooked_and_required() -> None:
    src = _read(BPF_SRC)
    # a release is reported at sys_exit, only when the call succeeded, in
    # whole pages
    for call in ("munmap", "madvise", "brk", "mmap", "mremap"):
        for side in ("enter", "exit"):
            assert f'SEC("tracepoint/syscalls/sys_{side}_{call}")' in src, call
        assert "pf_exit(PF_SYS_" in _section(src, f"int pf_{call}_exit(", "\n}\n"), call
    assert "PF_PAGE_ALIGN(c.len)" in _section(src, "int pf_munmap_exit(", "\n}\n")
    assert "PF_MREMAP_FIXED" in _section(src, "int pf_mremap_exit(", "\n}\n")
    # the address space ends by exec or teardown, not by inference
    assert 'SEC("kprobe/setup_new_exec")' in src and 'SEC("kprobe/exit_mmap")' in src
    attach = _section(_read(LOADER), "static int attach_pagefault(", "\n}\n")
    # a missing hook fails the start instead of overstating memory
    assert "return -ENOTSUP;" in attach
    for prog in ("pf_exec", "pf_mm_gone", "pf_munmap_exit", "pf_madvise_exit", "pf_brk_exit",
                 "pf_mmap_exit", "pf_mremap_exit"):
        assert f"pf_obj->progs.{prog}" in attach, prog
    assert "rmap->entry == CPA_PF_ENTRY_NONE" in attach


def test_live_set_is_written_per_second_without_counting_samples() -> None:
    unwind = _read("src/cpa_monitor/cpa_unwinder.c")
    branch = _section(unwind, "if (sample->pf.flags & PF_META_VALID) {", "\n\t}\n")
    assert "cli_stackmap_done_intern(" in branch
    assert "done_at" not in branch
    # the tracker is called after the tracemap lock is released
    assert branch.index("cpa_main_tracemap_unlock();") < branch.index("cpa_pagefault_on_alloc(")
    # the kernel part would only be the fault path
    body = _section(unwind, "static void cpa_unwind(struct unwind_worker *w", "\n}\n")
    assert body.index("if (sample->pf.flags & PF_META_VALID) {") < body.index("kernel_drop_stack_[k]")
    glue = _read(GLUE)
    for periodic in ("sleep(", "timedwait", "pthread_create"):
        assert periodic not in glue, periodic
    assert ".timer_fn = cpa_pagefault_timer_fn" in glue
    # values of a second add up: two ticks in one second write it once
    tick = _section(glue, "static void cpa_pagefault_timer_fn(", "\n}\n")
    assert "ctx.record_ms / STACKMAP_TIMEWHEEL_BUCKET_MS != pf.written_sec" in tick


def test_pagefault_is_single_process_only() -> None:
    configure = _section(_read(GLUE), "int cpa_pagefault_configure(", "\n}\n")
    # --pid, or a rule selection narrowed to one process by --first_match
    assert "spec->legacy_pid <= 0" in configure
    assert "!spec->first_match || spec->children || spec->n_pids" in configure
    capture = _read(CAPTURE)
    combos = _section(capture, "if (cpa_pagefault_configure(ctx))", "return CPA_INIT_FAILED;\n\t}")
    for arg in ('"offcpu"', '"oneshot"', '"probe"', '"enable_coredump_capture"', "exit_capture",
                '"ringbuf"'):
        assert arg in combos, arg
    assert '"--pagefault requires backend=bpf"' in _read("src/cpa_monitor/cpa_backend_preflight.c")


def test_input_is_taken_before_the_session_opens() -> None:
    """A --first_match process can exec as soon as bpf_capture_worker opens
    the target session: the tracker is active from the configuration on,
    which comes before the capture is set up, not from a later worker."""
    capture = _section(_read(CAPTURE), "static enum cpa_worker_init_result cpa_bpf_capture_init_fn(",
                       "\n}\n")
    assert capture.index("cpa_pagefault_configure(ctx)") < capture.index("cpa_bpf_oncpu_capture_init(ctx)") < \
        capture.index("cpa_target_start(")
    configure = _section(_read(GLUE), "int cpa_pagefault_configure(", "\n}\n")
    assert configure.index("pf.active = true;") < configure.index("stack_capture_set_pagefault(&cfg);")
    init = _section(_read(GLUE), "static enum cpa_worker_init_result cpa_pagefault_init(", "\n}\n")
    assert "pf.active = true" not in init
    assert "if (!pf.cold_start)" in init
    assert "cpa_target_latched_pid()" in _read(GLUE)
    # after bpf_capture_worker: the baseline scan runs with the hooks live
    assert ".worker_index = 11," in _read(GLUE)
    assert ".worker_index = 10," in _read(CAPTURE)


def test_cold_start_follows_the_target_ctl_latch() -> None:
    gate = _section(_read(BPF_SRC), "static __always_inline struct pf_config *pf_target_config(", "\n}\n")
    # no scalar pid: the shared target set target_ctl latched the winner into
    assert "target_task_tracked(" in gate
    load = _section(_read(LOADER), "static int load_pagefault(", "\n}\n")
    assert "prepare_target(pf_obj->maps.target_pids" in load
    # the exec's t0 CPU sample would be counted into a profile of bytes
    assert "set_autoload(pf_obj->progs.stack_capture_t0, false)" in load


def test_full_buffers_are_accounted_not_silent() -> None:
    src = _read(BPF_SRC)
    emit = _section(src, "static __always_inline void pf_report(", "\n}\n")
    assert "st->lost_pages" in emit and "st->lost_releases" in emit
    capture = _section(src, "static __always_inline int __stack_capture(", "\n}\n")
    assert "pf_stack_dropped(ctx, event);" in capture
    # the reader's PERF_RECORD_LOST counts, less the failures BPF saw, are
    # the unseen ones
    loader = _read(LOADER)
    attach = _section(loader, "static int attach_pagefault(", "\n}\n")
    assert "bpf_event_poll_register_lost(pf_events" in attach
    assert "pf_request.stack_lost_fn" in _section(loader, "int setup_stack_capture_event(", "\n}\n")
    glue = _read(GLUE)
    assert "beyond(pf.kernel_lost_stack, bpf.failed_stack_outputs)" in glue
    assert "case PF_DROPPED:" in glue
    assert "INCOMPLETE" in _section(glue, "static void check_losses_locked(", "\n}\n")
