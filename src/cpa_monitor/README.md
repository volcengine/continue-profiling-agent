# CPA Monitor Runtime

## Overview

`cpa monitor` drives the continuous profiling runtime.

The runtime owns a shared `cli_stackmap`, registers workers, persists profile data,
and coordinates:

- capture
- unwind / symbolization
- storage rotation
- local runtime statistics

## Active worker set

### env_worker
- Parses environment-related options and exposes env selection policy to the unwinder.

### bpf_capture_worker
- Loads and runs BPF-based stack capture and process-exit handling.
- Feeds `stack_queue` and `pid_exit_queue`.

### perf_capture_worker
- Provides the perf-based sampling backend.

### unwinder_worker
- Drains captured samples, invokes libgunwinder, and appends frames to the shared stackmap.

### pid_tracker_worker / ksyms_check_worker
- Maintains PID metadata for no-BPF unwind events and monitors `/proc/kallsyms` changes.

### stackmap_continous_worker
- Rotates storage directories and periodically flushes stackmap deltas to disk.

### stackmap_oneshot_worker
- Writes a single profile output when one-shot mode is enabled.

### cpa_stat_worker
- Prints local runtime health information and requests restarts when cache or store usage exceeds limits.

### debug_dump_worker
- Retained as a diagnostic helper for runtime debugging.

## Runtime lifecycle

1. runtime start
   - parses CLI options
   - initializes the shared stackmap
   - runs each worker `init_fn`
2. runtime loop
   - executes `main_worker_fn` workers on the main thread
3. timer thread
   - fires by `record_interval`
   - runs each worker `timer_fn`
   - triggers restart when needed
4. restart path
   - calls `pause_fn` in reverse order
   - rebuilds the shared stackmap
   - calls `restore_fn` in forward order
5. runtime stop
   - joins threads
   - destroys stackmap
   - runs `destroy_fn` in reverse order

## Data flow

1. Capture workers collect samples.
2. `unwinder_worker` resolves stacks and metadata.
3. Stackmap workers persist data to the active store directory.
4. `cpa show` / `cpa_show` consume the stored CPA data.

## Storage notes

- Continuous mode rotates dated directories below `store_dir`.
- One-shot mode writes a single `.prof` file.
- Config metadata is written alongside stored profile data for later `show` / TUI consumption.

## Related project docs

- Top-level overview: [`README.md`](../../README.md)
- Architecture: [`docs/en/architecture.md`](../../docs/en/architecture.md)
- Usage: [`docs/en/usage.md`](../../docs/en/usage.md)
- Build and test: [`docs/en/build.md`](../../docs/en/build.md)
