"""Source-level guards for the execution-time guard, coredump capture and
ring-buffer datapath features."""
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BPF = REPO / "bpf/src/stack_capture"
MON = REPO / "src/cpa_monitor"


def test_exec_time_guard_bpf_break_and_config():
    bpf = (BPF / "stack_capture.bpf.c").read_text(encoding="utf-8")
    h = (BPF / "stack_capture.h").read_text(encoding="utf-8")
    assert "bpf_exec_time_guard_ns" in h
    # user-stack copy loop aborts once the time budget is exceeded
    assert "copy_start_ns" in bpf
    assert "bpf_ktime_get_ns() - copy_start_ns" in bpf
    assert "bpf_exec_time_guard_ns" in bpf
    # slow comms get a forced payload through a BPF hash map
    assert "comm_stack_limit" in bpf
    assert "stack_capture_effective_size" in bpf


def test_exec_time_guard_userspace_throttles_slow_comm():
    cap = (MON / "cpa_bpf_capture.c").read_text(encoding="utf-8")
    assert "bpf_exec_time_guard_ms" in cap
    assert "stack_capture_set_comm_stack_limit" in cap
    loader = (BPF / "stack_capture.c").read_text(encoding="utf-8")
    assert "stack_capture_set_comm_stack_limit" in loader
    assert "STACK_CAPTURE_COMM_LIMIT_MAX_ENTRIES" in loader


def test_coredump_kprobe_and_signal_marker():
    bpf = (BPF / "stack_capture.bpf.c").read_text(encoding="utf-8")
    assert 'SEC("kprobe/do_coredump")' in bpf
    assert "BPF_KPROBE(stack_capture_coredump" in bpf
    assert "coredump_siginfo_prefix" in bpf
    assert "STACK_EVENT_COREDUMP" in bpf
    # signals are extracted at program entry (PTR_TO_CTX boundary)
    assert "bpf_probe_read(&cd_info" in bpf
    cap = (MON / "cpa_bpf_capture.c").read_text(encoding="utf-8")
    assert "enable_coredump_capture" in cap
    unwind = (MON / "cpa_unwinder.c").read_text(encoding="utf-8")
    assert "STACK_EVENT_COREDUMP" in unwind
    assert "COREDUMP" in unwind and "cpa_signal_name" in unwind


def test_ringbuf_dual_datapath():
    bpf = (BPF / "stack_capture.bpf.c").read_text(encoding="utf-8")
    assert "#ifdef CPA_USE_RINGBUF" in bpf
    assert "BPF_MAP_TYPE_RINGBUF" in bpf
    assert "bpf_ringbuf_output(&events_rb" in bpf
    assert "CPA_EMIT_EVENT" in bpf
    # separate wrapper compiles the ringbuf variant
    assert (BPF / "stack_capture_ringbuf.bpf.c").exists()
    cmake = (BPF / "CMakeLists.txt").read_text(encoding="utf-8")
    assert "stack_capture_ringbuf" in cmake
    loader = (BPF / "stack_capture.c").read_text(encoding="utf-8")
    assert "stack_capture_ringbuf_bpf__open" in loader
    assert "bpf_event_poll_register_ringbuf" in loader
    assert "libbpf_probe_bpf_map_type" in loader
    poll = (REPO / "bpf/src/common/bpf_event_poll.c").read_text(encoding="utf-8")
    assert "bpf_event_poll_register_ringbuf" in poll
    assert "ring_buffer__consume" in poll
    cap = (MON / "cpa_bpf_capture.c").read_text(encoding="utf-8")
    assert '"datapath"' in cap and "ringbuf" in cap and "perfbuf" in cap
    assert "stack_capture_set_datapath" in cap


def test_timer_path_honors_comm_filter():
    bpf = (REPO / "bpf/src/stack_capture/stack_capture.bpf.c").read_text(encoding="utf-8")
    branch = bpf  # python str
    # timer sampling must read the current task comm and filter on it, not pid only
    timer_idx = branch.index("if (is_timer) {")
    timer_region = branch[timer_idx : timer_idx + 700]
    assert "bpf_get_current_comm(&timer_comm" in timer_region
    assert "comm_diff(config->comm, timer_comm" in timer_region
    assert "SHOULD_RECORD_PID(tid" not in timer_region
