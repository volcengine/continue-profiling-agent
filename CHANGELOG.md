# Changelog

## v1.2.0

- Choose what to profile by process name (`--comm`), executable (`--exe`),
  cgroup (`--cgroup`, `--container_pid`) or several pids, with
  `--children`, `--new_only`, `--first_match` and `--startup_window`.
  Matching happens in BPF when a process starts or execs.
- `--enable_exit_capture` records the stack of a process that exits
  non-zero or is killed by a signal, together with the exit code;
  `--exit_comm`, `--exit_pid` and `--exit_target_env_*` pick which
  processes. `cpa show --list_core` / `--list_exit` (and `L` in the TUI)
  list coredump and exit stacks.
- `--pagefault` profiles a process's resident anonymous memory by the
  stack that first touched it, one snapshot per second
  (Linux 5.4 - 5.18 and 6.3+).
- `--unwind_workers N` unwinds user stacks on N threads; `--force_fp`
  unwinds with frame pointers only.
- `cpa capabilities` prints what the running kernel supports.
- Runs on 4.14 kernels and on 6.17.
- The in-memory stack map is much smaller: with 400k distinct stacks it
  went from 389 MB to 128 MB, and peak RSS from 475 MB to 226 MB. Store
  files are unchanged.
- arm64: samples in a leaf function no longer lose its caller. On 5.17+
  a large stack frame with untouched pages keeps its callers too.
- Bundles libgunwinder v2.0.0.

## v1.1.1

- arm64: DWARF unwinding no longer drops the caller of an innermost leaf
  frame (libgunwinder v1.0.1).
- First release with the ring-buffer datapath (`--datapath`), coredump
  capture (`--enable_coredump_capture`), the BPF execution-time guard
  (`--bpf_exec_time_guard_ms`) and portable packages for linux x86_64 and
  arm64.

## v1.0.0

First open-source release.
