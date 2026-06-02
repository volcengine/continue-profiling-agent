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
