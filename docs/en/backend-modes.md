# CPA Backends and Capability Checks

[Back to README](../../README.md)

## Overview

`cpa monitor` currently keeps two sampling backends:

- `bpf`
- `perf`

They are not equivalent.

- `bpf` is the full backend. It supports continuous on-CPU sampling, `offcpu`,
  `probe`, one-shot export, BPF-side filtering, and IRQOFF records.
- `perf` only supports continuous on-CPU profiling.

Because of that, CPA performs a backend preflight before the runtime starts and
then chooses one of three outcomes:

- continue with BPF
- print a `WARNING` and fall back to perf
- fail fast with an explicit error

## Kernel Features Used by the BPF Path

The current BPF backend depends on the following kernel and libbpf features.

### BTF / CO-RE

- a usable vmlinux BTF, or
- a user-supplied custom BTF through `--btf_path`

The capture path relies on CO-RE relocation. If the custom BTF path is unreadable
or not a valid BTF object, startup rejects it during preflight.

### BPF Program Types

Depending on mode, CPA checks:

- `BPF_PROG_TYPE_PERF_EVENT`
  - regular continuous on-CPU timer sampling
- `BPF_PROG_TYPE_TRACEPOINT`
  - `sched:sched_process_exit`
  - `tracepoint:<group>:<name>` style `--probe`
- `BPF_PROG_TYPE_KPROBE`
  - `offcpu`
  - `kprobe:` / `kretprobe:` style `--probe`

### BPF Map Types

The current capture path uses:

- `BPF_MAP_TYPE_HASH`
- `BPF_MAP_TYPE_ARRAY`
- `BPF_MAP_TYPE_PERCPU_HASH`
- `BPF_MAP_TYPE_PERF_EVENT_ARRAY`

### BPF Helpers

The preflight explicitly checks the helpers currently used by CPA:

- `bpf_get_stack`
- `bpf_perf_event_output`
- `bpf_probe_read_user`
- `bpf_probe_read_kernel`

### Attach Targets

CPA also validates the concrete attach targets that the requested mode needs:

- `sched:sched_process_exit`
- `finish_task_switch` for off-CPU capture
- the user-specified `--probe` target

So the check is not just “can the kernel load some BPF program.” It verifies
the actual helpers, program types, map types, and attach points required by the
selected mode.

## Startup Policy

`cpa monitor` performs the capability check before the runtime is started.

### 1. If the user explicitly selected `perf`

CPA rejects the request if perf-only mode is asked to carry options that perf
does not implement.

The current rejected combinations include:

- `--oneshot`
- `--offcpu`
- `--probe`
- `--pid`
- `--comm`
- `--kernel_stack`
- non-default `--stack_size`

The rule is intentional: unsupported options should not silently become no-ops.

### 2. If the request is on the BPF path

CPA validates:

- BTF availability
- required program types, map types, and helpers
- required attach targets

### 3. CPA then chooses fallback vs hard failure

Not every BPF failure is allowed to fall back to perf.

## Fallback Matrix

### Eligible for perf fallback

Only plain continuous on-CPU profiling can fall back. In practice that means:

- `backend=bpf`
- no `--oneshot`
- no `--offcpu`
- no `--probe`
- no `--pid`
- no `--comm`
- no `--kernel_stack`
- no non-default `--stack_size`

When this request fails the BPF preflight, CPA will:

- print a `WARNING`
- explain the missing capability
- switch to perf automatically
- explicitly tell you that perf has no IRQOFF records

### Not eligible for fallback

CPA hard-fails when BPF is unavailable for any of these modes:

- `--oneshot`
- `--offcpu`
- `--probe`
- `--pid`
- `--comm`
- `--kernel_stack`
- non-default `--stack_size`

The reason is straightforward: these features are either BPF-only or not
semantically preserved by the perf backend.

## Actual perf Backend Limits

The current perf backend only promises:

- continuous on-CPU profiling
- writing the same continuous store format consumed by `cpa show`
- keeping the reader/viewer path working when BPF is unavailable

The current perf backend does not provide:

- `offcpu`
- `probe`
- one-shot mode
- BPF-side `pid/comm/kernel_stack` filtering
- custom `stack_size` semantics
- IRQOFF records

Also, unlike the BPF path, the current perf path does not populate `cgroup_id`
from a kernel-side capture event, so that field can be `0` in perf-generated
stores.

## Warning and Error Messages

### Automatic fallback

CPA emits a warning like:

```text
WARNING: BPF capability check failed: <reason>. Falling back to perf backend; perf only supports on-cpu continuous profiling and provides no IRQOFF records.
```

### Hard failure

When the request relies on BPF-only semantics, CPA emits an error like:

```text
BPF capability check failed: <reason>. Requested mode requires BPF backend and cannot fall back to perf; perf backend only supports on-cpu continuous profiling.
```

## Practical Guidance

### When to force `--backend=bpf`

Use BPF explicitly when you need:

- `offcpu`
- `--probe`
- one-shot mode
- BPF-side filtering or kernel-stack-only semantics
- IRQOFF records

### When automatic fallback is acceptable

Fallback is reasonable when you only need:

- machine-level or service-level continuous on-CPU trends
- a usable store directory that `cpa show` can still consume
- continuity of collection, even if IRQOFF records disappear and cgroup
  metadata becomes less complete

## Design Tradeoff

Perf fallback exists because plain continuous on-CPU profiling is still useful
even when BPF is unavailable.

CPA deliberately does not extend that fallback to `offcpu`, `probe`, one-shot,
or BPF-side filtering, because silently changing semantics in production is
worse than failing fast.
