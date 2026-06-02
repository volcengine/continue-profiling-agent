from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CPA_RUNTIME_SOURCE = REPO_ROOT / "src/cpa_monitor/cpa_runtime.c"


def test_runtime_rejects_nonpositive_record_interval_before_timer_setup() -> None:
    source = CPA_RUNTIME_SOURCE.read_text(encoding="utf-8")
    interval_parse = "runtime.cfg.record_interval = atoi(get_arg_by_name(cli_ctx, \"record_interval\"));"
    stackmap_init = "runtime.trace_stackmap = cli_stackmap_init();"

    parse_offset = source.index(interval_parse)
    init_offset = source.index(stackmap_init)
    assert parse_offset < init_offset

    validation_window = source[parse_offset:init_offset]
    assert "runtime.cfg.record_interval <= 0" in validation_window
    assert "record_interval must be positive" in validation_window


def test_runtime_stop_wakes_timer_thread_before_joining() -> None:
    source = CPA_RUNTIME_SOURCE.read_text(encoding="utf-8")
    wait_start = source.index("static int cpa_wait_timer(void)")
    restart_marker = source.index("void cpa_runtime_need_restart(void)")
    wait_body = source[wait_start:restart_marker]

    assert "#include <sys/eventfd.h>" in source
    assert "runtime.stop_fd" in wait_body
    assert "struct pollfd fds[2]" in wait_body
    assert "eventfd_read(runtime.stop_fd" in wait_body

    stop_start = source.index("int cpa_runtime_stop(void)")
    loop_marker = source.index("void cpa_runtime_loop(void)")
    stop_body = source[stop_start:loop_marker]

    wake_offset = stop_body.index("cpa_runtime_wake_timer_thread();")
    join_offset = stop_body.index("cpa_runtime_join_timer_thread()")
    assert wake_offset < join_offset
