from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CPA_BPF_CAPTURE_SOURCE = REPO_ROOT / "src/cpa_monitor/cpa_bpf_capture.c"


def _function_body(source: str, signature: str) -> str:
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
    raise AssertionError(f"function body not found for {signature}")


def test_bpf_capture_tracks_and_disables_owned_modules() -> None:
    source = CPA_BPF_CAPTURE_SOURCE.read_text(encoding="utf-8")
    assert "process_exit_enabled" in source
    assert "stack_capture_enabled" in source
    assert "offcpu_capture_enabled" in source

    disable_body = _function_body(source, "static void cpa_bpf_capture_disable_modules")
    assert "DISABLE_MODULE_BPF(process_exit)" in disable_body
    assert "DISABLE_MODULE_BPF(stack_capture)" in disable_body
    assert "DISABLE_MODULE_BPF(offcpu_capture)" in disable_body
    assert "probe = NULL" in disable_body

    destroy_body = _function_body(source, "static void cpa_bpf_capture_destroy_fn")
    assert "cpa_bpf_capture_disable_modules();" in destroy_body


def test_bpf_capture_rolls_back_failed_setup_paths() -> None:
    source = CPA_BPF_CAPTURE_SOURCE.read_text(encoding="utf-8")

    init_body = _function_body(source, "static enum cpa_worker_init_result cpa_bpf_capture_init_fn")
    process_exit_setup = init_body[init_body.index("INIT_MODULE_BPF(process_exit)") : init_body.index("int offcpu")]
    assert "setup_process_exit_event(exit_event_process) < 0" in process_exit_setup
    assert "DISABLE_MODULE_BPF(process_exit)" in process_exit_setup
    assert "process_exit_enabled = true" in process_exit_setup
    assert "cpa_bpf_capture_disable_modules();" in init_body

    offcpu_body = _function_body(source, "static int cpa_bpf_offcpu_capture_init")
    assert "DISABLE_MODULE_BPF(offcpu_capture)" in offcpu_body
    assert "offcpu_capture_enabled = true" in offcpu_body

    oncpu_body = _function_body(source, "static int cpa_bpf_oncpu_capture_init")
    assert "if (!probe)" in oncpu_body
    assert "DISABLE_MODULE_BPF(stack_capture)" in oncpu_body
    assert "stack_capture_enabled = true" in oncpu_body
