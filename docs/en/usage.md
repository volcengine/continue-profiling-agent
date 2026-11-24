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
- `--force_fp`: unwind user stacks by frame pointers only, never DWARF:
  cheaper per sample for code built with frame pointers, but a frame without
  one ends or skips the stack. Ignored, saying so, on kernels without
  `bpf_get_stack` (before 4.18)
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

## Crash and Non-Zero Exit Stacks

`--enable_coredump_capture` records the stack of a process that dumps core,
at the dump. `--enable_exit_capture` records one stack per selected process
that ends non-zero through `exit_group(2)` or a fatal signal, before its
memory is released:

```text
<# EXIT NONZERO raw=768 exit=3 #>          exit(3); raw is the wait(2) status
<# EXIT NONZERO raw=15 sig=15 core=0 #>    killed by SIGTERM
```

Both are BPF on-CPU only: with `--offcpu`, `--oneshot`, `--probe` or
`--kernel_stack` (exit capture) they are refused at start. Their frames carry
symbol+offset, pc, build-id and the full path, for offline resolution.

Exit capture needs a target, since every process on the host passes the exit
hook: its own

- `--exit_comm <n1,n2>`: processes with these names (at most 8), or
- `--exit_pid <p1,p2>`: these running processes (at most 16), not both;

these choose exits only and leave sampling as it is. Without them the process
selection (`--pid`, `--comm`, ...) applies; system-wide exit capture is
refused.

`--exit_target_env_name MY_POD_NAME,POD_NAME` with
`--exit_target_env_values <v,...>` (exact) and/or
`--exit_target_env_value_prefix <p,...>` keeps only the exits of processes
whose first listed variable set to a non-empty value matched. It needs
`--exit_comm` or `--exit_pid`. The environment is read when the process is
selected (its exec or fork into an `--exit_comm` name, the start scan, or start
for `--exit_pid`), because it is gone at the exit; a process that exits before
it was read is dropped. The stats line shows `Exit Capture Count`, `Exit Env
Mismatch Drop` and `Exit Env Unknown Drop`.

Limits, by choice:

- a leader leaving by a raw `exit(2)` syscall with no group exit is not
  recorded (it would need a hook on every thread exit);
- an exit record may lack its user frames when the process' view of its
  mappings is missing the library it exits from: it was never sampled, or it
  was selected at exec and its view was read while its loader still ran
  (more likely with several `--unwind_workers`, which unwind that first
  sample sooner). A process' mappings are re-read at most once per 30-90 s,
  and the record is unwound after the process is gone, so nothing can be
  read then;
- when threads race `exit_group` with different codes, the first entrant's
  code is recorded.

To read them:

```bash
./build/bin/cpa show --read /var/log/cpa/cpa_YYMMDD --list_exit \
  --starttime 00:00:00 --endtime 23:59:59 --core_verbose
```

`--list_core` lists coredump samples, `--list_exit` exit samples (not both),
one block each with metadata, exit code and frames; the `--target_*` filters
apply. `--core_verbose` resolves native frames with addr2line (`CPA_ADDR2LINE`
overrides the tool), through the binary or a build-id debug file under
`/usr/lib/debug` or `--core_debug_dir`; `--core_container_pid <pid>` resolves
container paths through `/proc/<pid>/root`. In the TUI, `L` opens the same
list.

## Resident Memory by Allocating Stack

`--pagefault` profiles one process's resident anonymous memory instead of
CPU time: which stacks first touched the anonymous memory it still has
mapped. The value is **bytes**, and every second holds the live set of that
second, so the per-second total is the process's resident anonymous memory
curve and any single second is a flame graph of it.

```bash
# a running process
sudo ./build/bin/cpa monitor --pagefault --pid 12345

# cold start: the first "server" started in this cgroup, from its exec on
# (dynamic loader, libc initialisation, main() and everything after)
sudo ./build/bin/cpa monitor --pagefault --cgroup system.slice/app.service \
  --comm server --first_match

# every page instead of 1 in 16 (exact, more overhead)
sudo ./build/bin/cpa monitor --pagefault --pid 12345 --pf_sample_pages 1
```

- `--pagefault`: profile resident anonymous memory instead of CPU time;
- `--pf_sample_pages <N>`: record 1 in N 4 KiB pages (a power of two, 1 to
  512, default 16); larger pages in proportion, a 2 MiB THP always.

The process is `--pid` (one), or the one a rule selection (`--comm`, `--exe`,
`--cgroup`, `--container_pid`) picks with `--first_match`. `--children`,
several pids, rules without `--first_match`, `--offcpu`, `--oneshot`,
`--probe`, coredump or exit capture, `--kernel_stack`, `--datapath ringbuf`,
`--record_interval` other than 1 and the perf backend are refused at start.

What is counted:

- anonymous private pages the process faults in (heap, anonymous `mmap`,
  thread stacks, copy on write of such pages), charged to the stack that
  faulted them in as long as they stay mapped. Not counted: file pages
  (also copy on write of a private file mapping), shared memory, pages the
  kernel allocates for itself;
- a page leaves the profile when its range is unmapped (`munmap`, `mremap`
  shrink, `MAP_FIXED` or `MREMAP_FIXED` over it, `brk` shrink) or discarded
  (`MADV_DONTNEED`, `MADV_FREE`, `MADV_REMOVE`) by a call that succeeded;
  `mremap` moves keep the page and its stack. `exec` and the exit of the
  last thread empty the live set;
- sampling: each block of N aligned 4 KiB pages has one position in the
  sample, picked by a salted hash of its address; a page there counts N
  pages. A new page of k pages (a THP, a multi-size THP on 6.8+) with
  k >= N is always recorded with its size, with k < N when it covers its
  block's position. The estimate is unbiased; a 2 MiB THP is exact;
- pages already resident when `--pid` profiling starts are found once in
  `/proc/<pid>/pagemap` and charged to `[resident before profiling]` (a
  `--first_match` process has none: it is followed from its exec);
- a page whose stack could not be recorded still counts, under
  `[stack dropped]` or the pressure marker;
- when the live set can no longer be exact the log says
  `pagefault: INCOMPLETE ...` with what happened (a page or release the
  kernel had no buffer room for, an allocation unwound too late, an event
  past the 200 ms reorder window, a page of a size that cannot be read).

To read it, select a single second: `cpa show --starttime T --endtime T`
returns the record ending at T, the live set as of the snapshot taken
during T-1. A window of several seconds adds their snapshots up. The CPU
field is always 0.

Kernels (the start log names the entry, `pagefault: new anonymous pages from
...`; `cpa capabilities` reports it as `pagefault`):

| Kernel | New pages from | Status |
| --- | --- | --- |
| before 5.4 | | refused: a perf output into a full buffer fails without telling the BPF program, so a sampled page could be lost unreported |
| 5.4 - 5.18 | `page_add_new_anon_rmap(page, vma, address, compound)` | supported |
| 5.19 - 6.2 | | refused: the function lost the argument that tells a THP apart |
| 6.3 and later | `folio_add_new_anon_rmap()` only, the folio's size read through the kernel BTF | supported; 6.6 and 6.8 verified, other series start with a warning |

A kernel without BTF on 6.3+, a `struct folio` layout this build does not
know (6.18's `memdesc_flags_t`), and kernels with 16/64 KiB pages are refused,
saying why. Every hook must attach or the session does not start.

Limits, by choice:

- ways for memory to go or move that no hook follows stay in the profile:
  `MADV_COLLAPSE` (6.1+), `UFFDIO_MOVE` (6.8+), and from 6.13
  `process_madvise` of the process on itself and `MADV_GUARD_INSTALL`;
- a range moved by `mremap` keeps the pages sampled at its old addresses: if
  they are copied on write later (after a `fork`), the range can be
  overestimated up to twice (1-in-N sampling only);
- two threads changing one range at the same moment are ordered by the time
  their calls were entered; an `madvise` that fails with an error other than
  `ENOMEM` after doing part of its range counts as having done nothing;
- swapped-out pages stay in the profile until their range is released; a
  page written again after `MADV_FREE` before the kernel reclaimed it is
  missing from then on;
- glibc reuses heap memory it already touched without a new fault, so a
  leaking allocation can be charged to the stack that touched that memory
  first; run the target with `MALLOC_MMAP_THRESHOLD_=131072` to give large
  blocks fresh mappings;
- native stacks only. A runtime restart of the store (midnight, size limit)
  rebuilds the live set from `/proc/<pid>/pagemap`, charged to
  `[resident before profiling]`.

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

## `cpa capabilities`

Prints what the running kernel lets `cpa monitor` do, one `key: value` per
line. Each capability is probed by loading a small BPF program or map, not
guessed from the kernel version, so backports count:

```bash
sudo ./build/bin/cpa capabilities
```

```text
schema_version: 1
kernel.release: 5.15.152-amd64
capability.get_stack_perf_event.state: supported
capability.get_stack_perf_event.reason: probe_succeeded
capability.get_stack_perf_event.error_code: 0
...
```

A state is `supported`, `unsupported` (the kernel lacks it), `unavailable`
(no permission: run as root) or `probe_error` (with the errno in
`error_code`). The capabilities are:

- `get_stack_perf_event`, `get_stack_kprobe`, `get_stack_tracepoint`:
  `bpf_get_stack` for each program type; without all three the lite capture
  objects are used (see the kernel compatibility notes);
- `perf_event_program_load`, `kprobe_program_load`,
  `tracepoint_program_load`: the program types timer sampling, `--offcpu` /
  `--probe kprobe:...` and `--probe tracepoint:...` load;
- `process_exit`: the exit tracepoint program every run attaches;
- `coredump`: the `do_coredump` kprobe (`vfs_coredump` on 6.17+) of `--enable_coredump_capture`;
- `ringbuf`: the ring-buffer datapath (`--datapath auto` uses it when present);
- `pagefault`: a kernel entry for `--pagefault`'s new anonymous pages (5.4 -
  5.18, or 6.3+ with BTF; refused otherwise).

`cpa monitor` reads the same cached results when it picks its BPF objects.
`schema_version` changes only when a key changes meaning.

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
