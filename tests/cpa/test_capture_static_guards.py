"""Source-level guards for capture/storage behavior that is not
practical to exercise through a compiled harness here.
"""
from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def _body(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for offset in range(brace, len(source)):
        if source[offset] == "{":
            depth += 1
        elif source[offset] == "}":
            depth -= 1
            if depth == 0:
                return source[brace : offset + 1]
    raise AssertionError(f"body not found for {signature}")


def test_exit_event_size_is_validated() -> None:
    source = (REPO_ROOT / "src/cpa_monitor/cpa_bpf_capture.c").read_text(encoding="utf-8")
    body = _body(source, "static void exit_event_process")
    assert "if (sz < sizeof(struct process_exit_event))" in body
    # must be checked before any dereference of the event payload
    assert body.index("sizeof(struct process_exit_event)") < body.index("->ts")


def test_set_fd_limit_is_best_effort_and_called_early() -> None:
    common = (REPO_ROOT / "src/cli_common.c").read_text(encoding="utf-8")
    body = _body(common, "void set_fd_limit")
    assert "exit(" not in body
    assert "want > lim.rlim_max" in body
    assert "want = lim.rlim_max" in body
    assert "lim.rlim_cur = want" in body

    monitor = (REPO_ROOT / "src/cpa_monitor/cpa_monitor.c").read_text(encoding="utf-8")
    mbody = _body(monitor, "int SUB_CMD_FUNC(cpa_monitor)")
    assert "set_fd_limit(1048576);" in mbody
    assert mbody.index("set_fd_limit(1048576);") < mbody.index("cpa_runtime_start")


def test_pid_exit_cleanup_waits_for_grace() -> None:
    source = (REPO_ROOT / "src/cpa_monitor/cpa_unwinder.c").read_text(encoding="utf-8")
    assert "#define CPA_PID_EXIT_GRACE_NS (10ULL * 1000000000ULL)" in source
    body = _body(source, "static void cpa_handle_pid_exit_events")
    assert "queue_peek" in body
    assert "CPA_PID_EXIT_GRACE_NS" in body
    # FIFO head that is not ripe yet stops the drain
    assert "break;" in body


def test_unwinder_idle_polling_backs_off() -> None:
    source = (REPO_ROOT / "src/cpa_monitor/cpa_unwinder.c").read_text(encoding="utf-8")
    assert "CPA_UNWIND_IDLE_SLEEP_MIN_US 1000U" in source
    assert "CPA_UNWIND_IDLE_SLEEP_MAX_US 50000U" in source
    assert "cpa_unwinder_next_idle_sleep" in source


def test_btf_null_sentinels_treated_as_unset() -> None:
    source = (REPO_ROOT / "bpf/src/common/core.c").read_text(encoding="utf-8")
    assert 'strcmp(options->btf_path, "null") != 0' in source
    assert 'strcmp(options->btf_path, "/null") != 0' in source


def test_kernel_only_perf_pages_raised_to_four() -> None:
    source = (REPO_ROOT / "bpf/src/stack_capture/stack_capture.c").read_text(encoding="utf-8")
    assert "#define KERNEL_CAPTURE_PAGE_CNT 4" in source
    assert "#define USER_CAPTURE_PAGE_CNT 512" in source


def test_kernel_only_uses_fixed_event_buffer_and_size() -> None:
    bpf_source = (
        REPO_ROOT / "bpf/src/stack_capture/stack_capture.bpf.c"
    ).read_text(encoding="utf-8")
    assert "kernel_event_buf SEC(\".maps\")" in bpf_source
    branch = _body(bpf_source, "static __always_inline int __stack_capture")
    # coredump bypasses the kernel-only fast path so it keeps the user stack
    only_kernel = branch[branch.index("if (config->only_kernel && !is_coredump) {") :]
    assert "bpf_map_lookup_elem(&kernel_event_buf, &cpu)" in only_kernel
    # fixed, stack_size-independent output length
    assert "(u8 *)event, sizeof(struct stack_event))" in only_kernel

    userspace = (REPO_ROOT / "bpf/src/stack_capture/stack_capture.c").read_text(encoding="utf-8")
    # loader is datapath-generic (perfbuf/ringbuf skeletons) but resizes and
    # resolves the fixed kernel event buffer before load/by name.
    assert '"kernel_event_buf"' in userspace
    assert 'sc_map_fd("kernel_event_buf")' in userspace
    assert "sc_preload_resize" in userspace


def test_irqoff_throttle_baseline_and_drop_marker() -> None:
    source = (
        REPO_ROOT / "bpf/src/stack_capture/stack_capture.bpf.c"
    ).read_text(encoding="utf-8")
    assert "irqoff_post_throttle_drop SEC(\".maps\")" in source
    assert "stack_capture_consume_post_throttle_irqoff" in source
    assert "advance_irq_timestamp" in source
    assert "advance_filtered_irq_timestamp" in source
    # filtered paths advance the baseline instead of dropping it
    body = _body(source, "static __always_inline int __stack_capture")
    assert body.count("advance_filtered_irq_timestamp(") >= 4
    # both IRQOFF decision sites gate on the drop marker
    assert body.count("stack_capture_consume_post_throttle_irqoff(") >= 2
    # old zero-reset-on-throttle behaviour must be gone
    helper = _body(source, "static __always_inline void advance_irq_timestamp")
    assert "bpf_map_update_elem(&irq_stamp, &zero, time, BPF_ANY)" in helper


def test_cpa_show_accepts_empty_store() -> None:
    source = (REPO_ROOT / "src/cpa_show/cpa_show.c").read_text(encoding="utf-8")
    assert "if (dump_info.record_count == 0)" in source
    assert "No profile records recorded in this store" in source
