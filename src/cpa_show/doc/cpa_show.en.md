# cpa_show User Guide

> `cpa_show`: the terminal UI flamegraph viewer used by `continue-profiling-agent`.

---

## 1. Goal & Workflow

`cpa_show` opens a profile path.

Current supported format: the directory written by `cpa monitor`, with
`conf/strmap/idsmap/stack.bin` and the binary loader.

It provides:

- **CPU Trend**: CPU total (CPU) and kernel time (Sys) around the selected time window.
- **Flamegraph**: aggregated stacks for the current window, with zoom and aggregation direction.
- **Filters**: filter samples by `pid/comm/cpu/pod/cgid`.
- **Conf/Help/Status**: quick access to config and key hints.

Design notes:

1) Large files are read on-demand to keep startup fast.
2) Curves are computed incrementally; while the visible curve range is incomplete, the UI may busy-refresh until it becomes visible.
3) `strmap` symbols are demangled with `libiberty` and cached; template params can be stripped for readability.

Architecture:

- TUI depends on a stable UI-facing interface: `UiProfile` + `ProfileData`.
- Storage is loaded through the `binary-dir` loader.

---

## 2. Run & CLI Flags

Run (TUI):

```bash
cpa show --read /var/log/cpa/cpa_260129 --use_cui
```

Flags (aligned with `cpa show --use_cui`):

- `--read, -r <DIR>`: profile data directory (required)
- `--starttime, -B <HH:MM:SS>`: start time in the record timeline
- `--endtime, -E <HH:MM:SS>`: end time in the record timeline
- `--show_range, -p <0|1>`: print log time range and exit
- `--use_cache, -u <0|1>`: reuse `decompressed/` if exists (default 0; 0=overwrite, 1=reuse)

Additional flags:

- `--no-tui`: print summary only
- `--timing`: print startup timings to stderr

Note: `cpa_show` is built in-tree as the embedded Rust backend for `cpa show --use_cui`; it is not shipped here as a standalone executable.
`starttime/endtime` are absolute times matched against stored record
timestamps, not offsets from the first record. Use `--show_range` or the TUI
status bar to confirm the available timeline before selecting a range.

---

## 3. UI Areas & Metrics

The screen is usually split into three areas (use `g` to change chart height):

### 3.1 CPU Trend

- X-axis: time; `Sel:` is the selected window.
- Y-axis: **C** (core-equivalent usage). Left labels show `0C` and `maxC`, plus `NC` and `(N/2)C` when they are within the current y-range (`N` from `conf.cpu_num`).
- Colors: CPU (cyan), Sys (yellow). Green markers show window boundaries.
- Y max is computed from the visible range only (ceil of visible max).

### 3.2 Flamegraph

- Blocks: aggregated stack frames. Width is proportional to sample count.
- Selection: move by arrows/hjkl/ad; `Enter` zoom; `Esc` back.
- Detail line fields:
  - `samples`
  - `x.xxC/s (y.yyC)`: average cores per second and total core-seconds within the selected window
  - `View:xx.x%` (within current view)
  - `All:xx.xx%` (relative to whole machine `cpu_num`, computed from `C/s`)
  - `D:d/max Y:y`: depth/max-depth and vertical scroll offset (helps orientation on tall flamegraphs)

### 3.3 Status

- Render time, window duration (ms/s), node count, filter count, toggles, and recent status messages.
- Also shows the total dataset time range.

---

## 4. Keybindings

General:

- `[q]`: quit
- `[h]` / `?`: show or hide help; press the same key again to close it
- `[c]`: conf
- `[o]`: filters overlay

Time window:

- `[t]` / `[T]`: shift window forward/backward by span
- `[s]` / `[S]`: span +/-
- `[J]`: jump to an absolute time in the record timeline (`HH:MM:SS[.mmm]`)
- `[R]`: set an absolute time range in the record timeline

Chart:

- `[g]`: chart height
- `[0]`: full history
- `[9]`: back to default window (600s)

Flamegraph:

- arrows/hjkl/ad: move selection
- `[Enter]`: zoom in
- `[Esc]`: zoom out

Toggles:

- `[I]`: Caller/Callee aggregation
- `[N]/[P]/[M]/[D]/[C]/[H]/[O]`: Env/Pid/Comm/Cgid/Cpu/Thread/KernelOnly
- `[X]`: collapse `0x... [module]` as `<...> [module]`
- `[U]`: collapse IRQOFF CPU number

Filters (command line):

- `:`: open command prompt; `Esc` to cancel; `Enter` to apply
- `pid/pidv/cpu/cpuv/pod/podv/comm/commv/cgid/cgidv` and `unset <cmd>`

Note: the filters overlay (`[o]`) shows active filters in a command-like format (e.g. `cpu 0-3,7`).
