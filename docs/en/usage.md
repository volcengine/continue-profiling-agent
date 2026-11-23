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
- `--pid`, `--comm` and the other selection options: see
  [Choosing What to Profile](#choosing-what-to-profile)
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


## Choosing What to Profile

By default every process is sampled. These options narrow it down (BPF
backend only). Different options are combined with AND, comma-separated
values inside one option with OR; contradictory combinations are refused
when the command line is read.

- `--pid <p1,p2,...>`: these processes (at most 16)
- `--comm <n1,n2,...>`: processes with one of these names (at most 8). The
  name is checked when a process starts or execs, so a shell that execs into
  the name is picked up and a process that execs into something else is
  dropped. Names are exact and at most 15 bytes, as the kernel keeps them.
- `--thread_comm <name>`: threads with this name, alone or with a single
  `--pid` (the filter `--comm` used to be)
- `--exe <path1,...>`: processes running one of these executables, compared
  by device and inode (at most 4)
- `--cgroup <path1,...>`: processes in one of these cgroups, given relative
  to the cgroup v1 `cpu` mount or the cgroup v2 mount (at most 8);
  `--cgroup_recursive` adds their descendants, up to 8 levels. Needs a kernel
  whose cgroupfs gives cgroup ids to user space (upstream 4.15 and later; some
  vendor kernels earlier); refused otherwise.
- `--container_pid <pid>`: the processes in that process' cgroup and below it
- `--children`: also the processes the selected ones start, and theirs,
  including those already running when the monitor starts
- `--new_only`: only processes that start after the monitor is ready, which
  it logs as `target: waiting for a matching process` (startup takes about a
  second, longer on old kernels); a process started before that line is not
  selected
- `--first_match`: the first process that starts and matches, nothing else;
  the run stops once it exits or its startup window ends
- `--startup_window <sec>`: sample each selected process for this long after
  it is selected

Examples:

```bash
# every java process, including ones started later
sudo ./build/bin/cpa monitor --comm java

# the next process started from this binary, for its first 60 seconds
sudo ./build/bin/cpa monitor --exe /opt/app/bin/server --first_match --startup_window 60

# a container's processes
sudo ./build/bin/cpa monitor --container_pid 4242
```

The selection is kept in a BPF map: rules are checked once where a process is
born (exec, fork) and sampling only looks the process up, so a selection costs
nothing per sample beyond that lookup.

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
