# CPA Architecture

[Back to README](../../README.md)

## Overview

`continue-profiling-agent` is organized around two primary commands:

1. `cpa monitor` captures stack samples and writes a persistent profile store.
2. `cpa show` reads that store and renders either a flamegraph or the embedded
   Rust TUI.

## High-Level Data Flow

```text
kernel events / perf samples
            |
            v
  BPF or perf capture backend
            |
            v
       CPA runtime workers
            |
            v
    shared cli_stackmap state
            |
            v
  on-disk CPA profile directory
            |
            v
   cpa show / embedded cpa_show
```

## Main Components

## CLI Layer

Top-level CLI entry points live under `src/`:

- `cli.c`: root command dispatch
- `cpa_monitor/`: `cpa monitor`
- `cpa_show/`: `cpa show` and the FFI bridge into Rust
- `cli_*` helpers: stackmap parsing, directory management, metadata handling,
  config parsing, queues, and zstd helpers

The user-facing subcommands are:

- `cpa monitor`
- `cpa show`

## Runtime Layer

`cpa monitor` uses a worker-based runtime. Workers provide lifecycle hooks such
as `init`, `timer`, `main_worker`, `pause`, `restore`, `stop`, and `destroy`.

The worker set covers:

- BPF-based capture
- perf-based capture
- unwind and symbolization
- environment filtering support
- no-BPF unwind metadata tracking
- continuous store rotation
- one-shot store export
- local runtime statistics
- debug dump paths

The runtime owns the shared `cli_stackmap`, coordinates worker startup order,
handles periodic callbacks, and performs restart flows when caches or storage
limits require a rebuild.

The stack map keeps every frame string and stack of the store directory in
memory, so later samples dedupe against them, until the store restarts. A
stack is one record of varints, the delta of each frame's string id to the
previous one (about 1.5 bytes per frame), and strings and stacks live in
append-only arenas, found through open-addressed indexes of ids and hashes.
The stats line reports the arenas (`Ids/Str Alloc Size`), the id arrays and the
indexes; their sum is what `--max_cache_size_mb` compares. The files of a store
do not depend on this layout.

See [src/cpa_monitor/README.md](../../src/cpa_monitor/README.md) for the worker
breakdown.

### Unwind workers

User stacks are unwound by `--unwind_workers` threads (default 1). Worker 0
is the main thread's runtime loop; the others are threads started at init.
The unwind queue has one lane per worker, and a process (tgid) is hashed to
one lane for the whole session: its samples and its exit both go there. Each
worker has its own libgunwinder context, so a process' unwind state has one
writer and the unwind path takes no shared lock until the finished frames are
committed to the shared stack map in one short critical section. Kernel
symbols are loaded once, by context 0, and looked up through it by all
workers.

Admission is one budget for all lanes: queued plus in-flight samples stay
within `max_queue_size - 1 + workers`, and one busy process can fill its lane
as with one worker. An exit is reaped by its lane's worker after a 10 s grace
period and only once no sample of that process instance is still queued or
being unwound. Idle workers sleep on their lane's semaphore; a sample, the
first exit of a lane, a pause or a stop wakes them.

A restart (day rotation, cache or store limits) pauses all workers at a safe
point before the contexts are rebuilt; stop joins the extra workers before
the store worker flushes.

The trade-off: every context keeps its own copy of the debug information of
the libraries its processes map, so memory and the startup CPU spent loading
it grow with the worker count, and
a single process is never unwound faster than by one worker. Keep the
default unless the queue stays backed up (`Parse Queue Len` near the limit,
`PRESSURE DROP` samples).

## Capture Backends

CPA keeps two on-CPU capture backends:

- BPF backend
  - CO-RE BPF programs are built under `bpf/`.
  - Host-side loaders and event parsers live in `bpf/src/`.
  - Kernel stacks are collected with `bpf_get_stack()` and symbolized in
    user space.
- perf backend
  - Used as the alternate sampling source when BPF is not selected.

Optional capture modes include:

- off-CPU collection
- probe-triggered capture through `--probe`

## Storage Format

`cpa monitor` writes one profile directory per time bucket below `store_dir`.
Important files include:

- `conf`: runtime configuration snapshot
- `strmap`: string table used during symbol/materialized metadata lookup
- `idsmap`: compact stack identifier mapping
- `stack.bin`: time-ordered stack samples and record boundaries
- optional decompressed or derived files used by `cpa show`

The storage layout is consumed directly by `cpa show` and `cpa_show`. The
directory format, rather than a live RPC protocol, is the stable interface
between collection and viewing.

See also:

- [Store Format](store-format.md)
- [Backends and Capability Checks](backend-modes.md)

## cpa show and cpa_show

`cpa show` is the user-facing inspection command. It supports:

- time-range selection
- metadata-based filtering
- flamegraph export
- split export for selected ranges
- launching the embedded Rust TUI with `--use_cui`

`cpa_show` is not a standalone product in this repository. It is built as an
embedded Rust static library and called through the C-side FFI bridge.

The Rust side is organized around loaders and a UI-facing profile model. That
split keeps future storage-format evolution away from the terminal UI logic.

See:

- [src/cpa_show/README.md](../../src/cpa_show/README.md)
- [src/cpa_show/doc/cpa_show.en.md](../../src/cpa_show/doc/cpa_show.en.md)

## Build Structure

Key build relationships:

- top-level CMake drives the full build
- `cmake/cpa.cmake` assembles the `cpa` executable
- `bpf/` builds BPF objects, loaders, and generated artifacts
- `libs/libgunwinder` is tracked as a Git submodule, built from source,
  copied as `libgunwinder.so` next to `cpa`, and linked dynamically through
  `$ORIGIN`
- `src/cpa_show/rust/` is built with Cargo as a static library

The BPF host-side code is compiled into the main executable through the
`cpa_bpf_core` object target instead of being shipped as a reusable standalone
library.
