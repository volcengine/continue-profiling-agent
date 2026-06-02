# CPA Usage Guide

[Back to README](../../README.md)

For the full public option reference, see the `Option Reference` section in
[README.md](../../README.md).

## Prerequisites

- build `build/bin/cpa`
- run on Linux with the required BPF/perf capabilities
- use root privileges for most `cpa monitor` workflows

## `cpa monitor`

`cpa monitor` collects samples and writes profile data into `store_dir`.

Basic continuous profiling:

```bash
sudo mkdir -p /var/log/cpa
sudo ./build/bin/cpa monitor \
  --store_dir /var/log/cpa \
  --freq 49
```

Useful options:

- `--backend bpf|perf`: choose the sampling backend
- `--pid <pid>`: limit capture to one process
- `--comm <name>`: limit capture by command name
- `--record_interval <sec>`: control the storage/query granularity
- `--persistent_day <days>`: retain only recent profile directories
- `--record_env_name <k1,k2>`: persist selected environment keys for later
  filtering in `cpa show`
- `--parse_env_values <v1,v2>`: only unwind user stacks for matching
  environment values
- `--bench`: print per-stat-interval final-DWARF-path benchmark statistics,
  including actual unwind count, rate, average/min/max latency, and fixed
  latency buckets. `FP_BETTER` samples are excluded. Initial symbol/CFI cold
  loading can appear in the first few intervals.

One-shot profiling:

```bash
sudo ./build/bin/cpa monitor \
  --pid 12345 \
  --oneshot \
  --output_prof /tmp/cpa.prof
```

Off-CPU collection:

```bash
sudo ./build/bin/cpa monitor \
  --pid 12345 \
  --offcpu 1
```

Probe-triggered capture:

```bash
sudo ./build/bin/cpa monitor \
  --pid 12345 \
  --probe kprobe:try_to_free_pages
```

Perf backend:

```bash
sudo ./build/bin/cpa monitor \
  --backend perf \
  --store_dir /var/log/cpa
```

## `cpa show`

`cpa show` reads a stored profile directory.

Print the available time range:

```bash
./build/bin/cpa show \
  --read /var/log/cpa/cpa_YYMMDD \
  --show_range 1
```

Export one flamegraph:

```bash
./build/bin/cpa show \
  --read /var/log/cpa/cpa_YYMMDD \
  --output_prof cpa.prof
```

Without an explicit time range, this exports from the first record that matches
the selected filters.

Select an absolute time range from the stored record timeline:

```bash
./build/bin/cpa show \
  --read /var/log/cpa/cpa_YYMMDD \
  --starttime 00:10:00 \
  --endtime 00:15:00 \
  --output_prof cpa.prof
```

Common filtering options:

- `--target_pid <pid>`
- `--target_comm <name>`
- `--target_env <value>`
- `--target_cgroup_id <id>`
- `--target_cpu <set>`

Other useful options:

- `--show_thread_name 1`: include thread names in the flamegraph
- `--no_pid 1`: suppress pid suffixes in rendered stacks
- `--no_env 1`: suppress env labels in rendered stacks
- `--show_raw 1`: include raw metadata in the flamegraph
- `--output_num <n>`: export `n` records from the selected time point; use a
  positive integer
- `--split_path <dir>`: export the selected range as split raw files

Launch the embedded Rust TUI:

```bash
./build/bin/cpa show \
  --read /var/log/cpa/cpa_YYMMDD \
  --use_cui
```

The TUI supports time-range browsing, flamegraph zoom, and interactive filters.
Detailed TUI behavior is documented in
[src/cpa_show/doc/cpa_show.en.md](../../src/cpa_show/doc/cpa_show.en.md).

## Output and Storage Notes

- The default continuous store root is `/var/log/cpa`.
- The default one-shot output path is `cpa.prof`.
- `cpa show` expects a directory written by `cpa monitor`, not an arbitrary
  flamegraph text file.
- `--use_cache 1` allows `cpa show` to reuse decompressed intermediate files.

## Typical Workflow

1. Start `cpa monitor` on the target workload.
2. Wait until one or more profile directories are written.
3. Use `cpa show --show_range 1` to inspect the available time span.
4. Export a flamegraph or open the TUI for interactive analysis.
