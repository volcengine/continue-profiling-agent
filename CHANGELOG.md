# Changelog

## v1.2.0 (unreleased)

Requires libgunwinder 2.0 (the bundled submodule).

### New

- **Process selection** done in BPF where processes are born: `--comm`,
  `--exe`, `--cgroup` (with `--cgroup_recursive`), `--container_pid`, several
  pids in `--pid`, `--children`, `--new_only`, `--first_match` and
  `--startup_window`. Refused combinations fail at start.
- **Exit stacks**: `--enable_exit_capture` records one stack per selected
  process that ends non-zero through `exit_group(2)` or a fatal signal, with
  its exit code; `--exit_comm`, `--exit_pid` and `--exit_target_env_*` choose
  which. `cpa show --list_core` / `--list_exit` list coredump and exit samples
  (`--core_verbose` resolves source lines), and the TUI has an `[L]` panel.
- **Resident memory by allocating stack**: `--pagefault` profiles one
  process's resident anonymous memory in bytes, one live set per second, with
  `--pf_sample_pages` sampling. Linux 5.4 - 5.18 and 6.3+; 6.6 and 6.8
  verified.
- `--unwind_workers N`: several threads unwind user stacks, each process by
  one of them.
- `--force_fp`: user stacks by frame pointers only.
- `cpa capabilities` prints what the running kernel lets the BPF backend do,
  each fact probed by loading a program or map.

### Kernels

- Kernels before 5.3 (4.14 validated) load lite capture objects: kernel
  stacks by stack id, a 16 KiB user stack copy, no frame-pointer stack.
- Where `bpf_find_vma` exists (5.17+, and backports), the on-CPU user stack
  copy is bounded by the VMA holding SP: no reads past the stack, holes inside
  it zero-filled, nothing read from I/O or PFN mappings.
- Linux 6.15 - 6.17: `kernfs_node::__parent`, `vfs_coredump`, FRED stack
  padding, `.cold` symbols.

### Changes

- The live stack map keeps stacks as delta-varint records in arenas: about
  a third of the memory for the same data; store files unchanged.
- A process is identified by its start time in clock ticks, its sampled
  thread travels with every event, and samples are keyed by their process.
- `--enable_coredump_capture` outside continuous on-CPU sampling is refused
  instead of ignored.

### Fixes

- A failed BPF capture init no longer leaves a monitor running without
  samples.
- The BPF event thread is joined before exit (an exit could livelock 4.14
  kernels in `do_exit`).
- A stack whose interning or counting fails no longer leaks its frames into
  the next one.
- arm64: a sample in a leaf function that saved nothing no longer loses the
  leaf's caller (libgunwinder).
- `--children` also selects descendants already running at start.
- The `--bench` histogram has a bucket for 4096 us and more.
- BPF objects are rebuilt when a header they include changes.

### Tests and CI

- `.github/workflows/ci.yml`: build, TUI tests, unit and static tests, and a
  root smoke run on x86_64 and arm64 for every push and pull request.
- New end-to-end suites for exit capture, page faults, process selection,
  unwind workers and the VMA-bounded copy; see docs/en/testing.md.

## v1.1.1

Release workflow and version fixes.

## v1.1.0

Ring-buffer datapath, coredump capture and capture hardening.

## v1.0.0

First open-source release.
