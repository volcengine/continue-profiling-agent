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
as `init`, `timer`, `main_worker`, `pause`, `restore`, and `destroy`.

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

See [src/cpa_monitor/README.md](../../src/cpa_monitor/README.md) for the worker
breakdown.

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
