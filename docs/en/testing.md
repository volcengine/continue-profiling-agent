# CPA Test Coverage Guide

This document describes the current test suites kept in the repository, the
behaviors each suite covers, and the environment assumptions required to run
them.

## Default Test Suite

Run the default open-source suite with:

```bash
pytest -q tests/cpa
```

The default suite currently includes:

- `tests/cpa/test_basic.py`
  - basic CLI behavior
  - fallback and error paths when BPF prerequisites are missing
  - `--btf_path` behavior
  - rejection of BPF-only options on the perf backend
- `tests/cpa/test_cpa.py`
  - on-CPU sampling frequency bounds for the default and perf backends
- `tests/cpa/test_date_rotation.py`
  - cross-day store rotation
  - same-day `_start_` naming
  - retention cleanup
  - cross-day `show_range` windows
- `tests/cpa/test_general_cli.py`
  - global help, subcommand help, and version output
  - rejection of unsupported and unknown options
  - public `show --help` wording
- `tests/cpa/test_kernel_modules.py`
  - `kworker` kernel-module sample capture
  - `IRQOFF` sample capture on the BPF backend
- `tests/cpa/test_ksyms_reload.py`
  - runtime reload behavior after `kallsyms` changes
- `tests/cpa/test_monitor_show.py`
  - the `monitor -> show` main flow
  - `show_range`
  - `output_num`
  - invalid time-range and corrupted-input handling
  - default one-shot output naming
- `tests/cpa/test_offcpu_probe.py`
  - `offcpu` and `probe` in normal and one-shot modes
  - OFFCPU thread/process metadata contract
- `tests/cpa/test_capabilities.py`
  - compiles a unit test of the capability model (`bpf/src/common/capabilities.c`):
    probed once, each probe result kept with its reason
  - `cpa capabilities` prints every capability with a valid state
- `tests/cpa/test_unwind_queue.py`
  - compiles a unit test of the unwind queue lanes and the per-sample frame
    buffer, plain, with ASan/UBSan and with TSan: routing by process, the
    shared admission budget and exit capacity, an exit waiting for the
    samples of its instance, wake-ups (a lane's own, all on stop, the first
    exit of a lane) and the frame buffer mirroring a stack map entry
- `tests/cpa/test_unwind_workers_e2e.py`
  - bad `--unwind_workers` values are refused before any worker starts;
    with 1 and 4 workers every sampled process gets user frames
- `tests/cpa/tools/cpa_unwind_workers.sh`
  - a `TEST_CPA_PATH` wrapper adding `--unwind_workers=4` (or
    `$CPA_UNWIND_WORKERS`) to every monitor run, to run the whole suite
    with several workers. `test_cpa_multi_workload_hot_stacks_and_cpu_budget`
    keeps its one-worker budget (0.5 cores over a 30 s run) and is expected
    to exceed it there: each worker's context loads the debug information of
    the shared libraries again at startup (on a 56-core host, about 0.7 cores
    over the run with 4 workers; steady state 5% of a core against 2.5%)
- `tests/cpa/tools/build_sanitized.sh tsan|asan OUT` and
  `tests/cpa/tools/stress.sh CPA_BIN WORKERS SECONDS OUTDIR [monitor args]`
  - build cpa and libgunwinder with TSan or ASan
    (`-DCPA_BPF_ENABLE_TSAN=ON` / `-DCPA_BPF_ENABLE_ASAN=ON`; libgunwinder is
    rebuilt from a copy, since its in-tree build ignores flag changes), then
    sample the whole system under a fork storm and busy processes; the run
    passes with 0 sanitizer reports. `MIDNIGHT_IN=S` (libfaketime, ASan
    builds only: libfaketime breaks TSan's clock) crosses midnight after S
    seconds, so every worker is paused and restored once
- `tests/cpa/test_exit_target_parse.py`, `tests/cpa/test_exit_env.py`
  - `--exit_comm` / `--exit_pid` / `--exit_target_env_*` parsing and refusals;
    the env store against real child processes (exact and prefix matches, the
    first listed name set, none set, gone, per instance, the reader thread),
    plain, with ASan/UBSan and with TSan
- `tests/cpa/test_exit_capture_e2e.py` (`tests/cpa/exit_capture/`)
  - with 1 and 4 unwind workers, copies of `exit_app` take one exit path each:
    exit_group from a worker, leader pthread_exit then a worker's exit or a
    SIGKILL, SIGTERM, racing exit_group (one sample), SIGSEGV, exit 0 and a raw
    SYS_exit (none), exec (none), coredump beside exit capture (COREDUMP only),
    `--exit_comm` / `--exit_pid` / `--exit_target_env_*` (start scan, exec,
    fork, mismatches, unknowns, the 4.14 exec fallback); every refused
    combination; `cpa show --list_exit`. The monitor's Exit Capture Count must
    equal the records

  - compiles a unit test of `src/cpa_monitor/cpa_target.c`: which option
    combinations select through the target set, which keep the pid/thread
    filter, and which are refused
- `tests/cpa/test_target_select_e2e.py`
  - `--comm`, a `--pid` list, `--exe`, `--new_only`, `--children`,
    `--first_match` (the run ends by itself) and `--startup_window` sample
    exactly the processes they name; bad combinations are refused
- `tests/cpa/test_stack_sample_builder.py`
  - compiles `tests/cpa/test_stack_sample_builder.c`, plain and with
    AddressSanitizer/UndefinedBehaviorSanitizer; no root needed
  - the sample pool (first fit, zeroed allocations, use after destroy)
  - which task a sample shows and which process it is keyed by, on and off
    CPU, and what libgunwinder is told (process and sampled thread)
  - sample weights for off-CPU and IRQ-off samples, kernel-thread and
    dropped samples
- `tests/cpa/test_workload_coverage.py`
  - multi-workload hot-stack coverage
  - CPU-budget checks for the default and perf backends
  - `record_env_name`
  - `sym_go_anon`
- `tests/cpa/test_asan_e2e.py`
  - only runs on ASan builds
  - ASan end-to-end `monitor -> show` smoke for both default and perf backends

## Environment Requirements

Many tests in the default suite require:

- a built `build/bin/cpa`
- root privileges
- a kernel and toolchain capable of loading the bundled fixture modules
- build tools used by the test fixtures, such as Python, gcc, cargo, and go

In particular:

- `test_kernel_modules.py` depends on kernel-module build and `insmod/rmmod`
- `test_ksyms_reload.py` depends on observable `kallsyms` changes
- `test_asan_e2e.py` depends on a separate ASan build

## ASan Tests

See the [Build Guide](build.md) for ASan build and execution commands.

Current ASan rules:

- `tests/cpa/test_asan_e2e.py` is the default ASan end-to-end gate
- the multi-workload CPU-budget assertion is not a failure gate under ASan
- the goal of ASan runs is memory-safety detection, not release-mode
  performance enforcement

## Design Principles

The current test suite keeps only behavior-level tests around the public
product surface.

Priority is given to coverage of:

- user-visible CLI behavior
- the `monitor/show` main flow
- real capture results on both the BPF and perf backends
- kernel-module and BPF-feature-critical behavior
- observable `cpa_show` input/output contracts
