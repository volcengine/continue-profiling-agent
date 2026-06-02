# CPA Technical Deep Dive: Keeping Performance Evidence Available

This document explains the design choices behind CPA. It focuses on why
continuous profiling is not the same as keeping a one-shot profiler always
enabled, and how CPA combines libgunwinder, BPF/perf capture, online unwinding,
and rolling storage to keep useful profiling history on production hosts.

For additional background, the CLK 2025 talk slides for this project provide
a compact architecture overview and motivation: [Continuous Profiling at CLK
2025](https://github.com/ChinaLinuxKernel/CLK2025/blob/main/4%20%E8%B0%83%E5%BA%A6%E3%80%81%E6%80%A7%E8%83%BD%E4%B8%8E%E8%B0%83%E8%AF%95%E5%88%86%E8%AE%BA%E5%9D%9B/2%20%E7%AB%A0%E9%9B%A8%E5%AE%B8-%E6%8C%81%E7%BB%ADProfiling.pdf).

## Keywords And Strengths

- Low CPU overhead: the cost scales with sample frequency, active CPU count,
  stack depth, and the number of active ELF objects. At 19 Hz on large active
  hosts, the design target is to keep whole-machine overhead below roughly one
  CPU core.
- Low memory overhead: libgunwinder keeps only the CFI and symbols needed by
  continuous unwinding, and shares same-build-id ELF indexes across processes.
- Low storage overhead: CPA does not persist full `perf.data`; it stores string
  dictionaries, stack ID dictionaries, and per-window counters. Typical output
  is in the KB/s range.
- Second-level whole-machine flamegraphs: continuous sampling and aggregation
  make short stalls visible after the fact.
- IRQ-Off support: the BPF backend can feed long IRQ-disabled paths into the
  same flamegraph pipeline.
- Production deployment model: CPA is designed as a resident recorder rather
  than an operator-triggered capture tool.

On a typical 16-core application host, the target steady cost is around
0.04 CPU core, about 200 MB of memory, and about 100 MB/day of storage, with
automatic store rotation.

## The Problem CPA Solves

![Missed perf captures and replayable CPA history](../assets/technical-deep-dive/01-missed-perf-cpa.png)

The hard part of production performance debugging is often not a lack of
metrics. Metrics can tell us that something happened, but they usually cannot
tell us which execution path was running at that exact moment. A CPU spike, a
system-call increase, or a scheduler stall may leave only a short bump on a
monitoring chart. By the time an engineer sees the alert, logs in, and prepares
to capture data, the event is already gone.

The usual workflow depends on either reproducing the issue or preparing a
trigger that catches the next occurrence. That makes diagnosis depend on the
assumption that the problem will happen again.

CPA changes that model. It turns one-shot post-event profiling into a
low-overhead recording capability: continuously sample, continuously unwind,
and continuously aggregate. After an incident, the question becomes not
"can we reproduce it", but "what did the stacks look like during that second".

## What CPA Provides

After CPA is installed, recent second-level flamegraph history is retained on
the host and rotated by policy. `cpa show` can export folded/flamegraph data, or
open the embedded TUI for interactive inspection.

![CPA TUI](../assets/technical-deep-dive/02-cpa-tui.png)

## Capabilities And Resource Cost

| Dimension | Notes |
| --- | --- |
| CPU cost | Depends on sample frequency, active CPUs, DWARF unwind ratio, and stack depth. |
| Memory cost | Mostly depends on the active ELF CFI and symbol working set. |
| Storage cost | Stores aggregated stack dictionaries and time-window counters. |

| Scenario | Host size | Active CPU | Active ELF | CPU cost | Memory | Storage |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| ClickHouse workload host | 128C / 1.5T | 67C | 253 | 0.10C | 2.5G | 100M/day |
| Dedicated MySQL host | 128C / 1.0T | 14C | 384 | 0.02C | 1.0G | 173M/day |
| Container host, about 100 pods | 256C / 1.0T | 143C | 2679 | 0.26C | 6.9G | 470M/day |

The exact numbers are less important than the shape of the cost model. CPA cost
is driven by active sample volume, active ELF working set, and retention period.
Higher sample frequency and more active CPUs increase CPU cost. More active ELF
objects increase resident CFI and symbol memory. Longer retention increases
store size.

## Why Not Keep perf Always Enabled

Perf is one of the most important Linux performance tools. Its model is clear:

1. `perf record` captures registers, stack memory, and event metadata.
2. `perf report` reads `perf.data` offline, loads ELF/CFI/symbol information,
   and reconstructs call stacks.

That two-stage design is excellent for a general-purpose analysis tool. The
recording phase is simple, while the reporting phase can handle symbolization,
source locations, debuginfo parsing, and rich post-processing.

For long-running online profiling, the same model becomes expensive. Consider a
200-core host sampled at 19 Hz with 64 KB of user stack copied per sample:

```text
200 * 19 * 64 KB ~= 243 MB/s
243 MB/s * 86400 ~= 20 TB/day
```

That does not include later `perf report` IO, debuginfo loading, compressed
section decompression, or DWARF expression evaluation. Perf is suitable for a
high-quality one-shot analysis, but it is not designed for whole-machine,
always-on, second-level history retention.

CPA defines a different problem. It does not keep a large raw capture and wait
for offline analysis. It unwinds and aggregates immediately after sampling, and
keeps only the data needed for later performance queries.

## libgunwinder: A Minimal Hot Path For Continuous DWARF Unwinding

The key question for continuous profiling is not whether unwinding is possible.
The key question is whether thousands of unwinds per second can be sustained
indefinitely. General-purpose unwinders usually target a wider debugging use
case: source lines, type information, variables, debugger queries, and offline
analysis. CPA needs a much smaller hot set:

1. CFI, to recover the previous frame.
2. Symbols, to map addresses to function names.
3. Process maps, to map PCs to ELF objects.

libgunwinder intentionally parses only the minimal data needed by continuous
unwinding and organizes it as memory indexes suitable for online lookup.

When libgunwinder first sees a process, it reads executable mappings, identifies
the corresponding ELF files, extracts CFI and symbols, and builds range indexes.
During unwinding, it finds the CFI for the current PC and uses the sampled
registers and stack snapshot to compute the previous PC.

![libgunwinder hot path](../assets/technical-deep-dive/03-libgunwinder-hot-path.png)

The important change is the shape of the whole path. File reads, debuginfo
decompression, and generic object models are removed from each-frame unwinding.
After warm-up, each frame should stay on the memory-query path instead of going
back to file IO or general debugger abstractions.

Once the hot path is fully memory-backed, continuous unwinding becomes a
resident system capability instead of a short-lived debugging action.

## ELF-Level Sharing: Do Not Load debuginfo Per Process

If every process loaded its own copy of libc, libstdc++, or shared application
libraries, continuous profiling would quickly become memory-bound. libgunwinder
moves debuginfo ownership from the PID level to the ELF level:

1. Each ELF is keyed by build-id or an equivalent digest.
2. Multiple processes mapping the same ELF share one CFI and symbol object.
3. Each process keeps only its own maps and references to ELF objects.
4. ELF objects are lifetime-managed by reference counting.

![ELF-level sharing](../assets/technical-deep-dive/04-elf-sharing.png)

This turns the system from "each process owns its debuginfo" into "the host
shares one unwindable working set". CPA memory is not simply a larger cache of
debuginfo; it is a shareable, reclaimable, and indexed online working set.

## IRQ-Off: Preserve Short Kernel Stalls

Many production stalls do not appear as long CPU hotspots. A CPU may simply
keep interrupts disabled for a short period, making userspace observe a small
"machine pause". This is important for latency-sensitive systems, but coarse
10-second or 30-second averages often hide it, and reproducing it later can be
hard.

IRQ-Off capture fills that blind spot. The BPF backend can capture stacks when
IRQ-disabled latency crosses the configured threshold and feed those samples
into the same unwind and stackmap aggregation path. The final result is not an
abstract latency spike, but the kernel path where the CPU stayed while
interrupts were disabled.

Regular CPU profiling answers "where was CPU time spent". IRQ-Off capture
answers "which path kept a CPU from responding to interrupts for too long".
Those events are short, and that is exactly why they need continuous recording.

## Storage: Keep Queryable History, Not perf.data

Continuous profiling has to optimize storage as well as CPU. If raw folded stack
strings are written for every sample, storage becomes another bottleneck. CPA
splits flamegraph data into stable dictionaries and per-window counters:

1. Function strings go into the string map.
2. A call stack becomes a stack ID.
3. Each time window stores only stack IDs and counts.

For example, a raw folded stack:

```text
start;main;handle_request;do_syscall 7
```

can be persisted as:

```text
strmap:
  start -> 1
  main -> 2
  handle_request -> 3
  do_syscall -> 4

idsmap:
  1;2;3;4 -> stack_id 42

time window:
  stack_id 42 -> count 7
```

This format gives up some raw-event completeness in exchange for feasible
long-term retention. CPA does not try to preserve every sample as a standalone
event forever. It keeps the information needed for the main performance
question: which call stacks consumed CPU in a given time window.

## Design Trade-Offs

libgunwinder and CPA choose a different set of trade-offs from offline profilers.

Accepted costs:

1. First-time warm-up when a new process or ELF is seen.
2. A resident minimal unwindable working set.
3. No full raw stack snapshots by default.
4. No debugger-level source-line or language-runtime semantics by default.

Capabilities gained:

1. The unwind hot path avoids file IO.
2. Second-level history can be retained for days.
3. Incidents can be inspected after they happen.
4. Whole-machine performance activity can be recorded continuously.

CPA is not a replacement for perf. Perf remains the right tool for deep one-shot
analysis, event-level debugging, and offline forensics. CPA is closer to a
flight recorder: it may not keep every debugging detail, but it continuously
records enough evidence to explain what the system was doing when an incident
happened.

## Measurements: From Microbenchmarks To Real Workloads

The data can be read in three layers:

1. libgunwinder CFI microbenchmark: how fast CFI lookup and expression
   evaluation can be.
2. ClickHouse workload dump: end-to-end unwinding cost on complex C++ stacks.
3. CPA bench: total cost when sampling, unwinding, aggregation, and storage run
   together.

### CFI bench

The machine was an Intel Xeon Platinum 8336C @ 2.30 GHz running Linux 5.15.152
with GCC 8.3.0. Runs were pinned to CPU0 to avoid migration and concurrency
noise.

| Working set | CFI frames/s | Avg ns/frame | P50 ns | P99 ns | 16-frame samples/s | 32-frame samples/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | 11,998,307 | 83.35 | 70.11 | 167.27 | 749,894 | 374,947 |
| 1,000 | 4,227,484 | 236.55 | 228.41 | 327.33 | 264,218 | 132,109 |
| 10,000 | 1,353,664 | 738.74 | 737.73 | 862.48 | 84,604 | 42,302 |

Even with a 10,000-entry working set, the CFI hot path stays below 1 us per
frame on average. End-to-end CPA cost is higher because it also includes map
lookups, stack snapshot access, symbol handling, aggregation, and runtime
scheduling. The important conclusion is that CFI evaluation itself is not the
main blocker for continuous unwinding.

### ClickHouse workload dump

The following data comes from end-to-end DWARF unwinding on a ClickHouse
workload dump. It is closer to a real C++ production workload than the CFI
microbenchmark: deeper stacks, more ELF files, and more complex CFI
distribution.

| Metric | Result |
| --- | --- |
| Samples | 360 |
| Average stack depth | About 36 frames or less |
| Maximum observed stack depth | 63 frames |
| Stable DWARF unwind throughput | 8.8k to 11.3k unwinds/s |
| Stable DWARF average latency | 88 us to 114 us |
| Stable DWARF P50 | 81 us to 104 us |
| Stable DWARF P95 | 150 us to 181 us |
| Stable DWARF P99 | 189 us to 213 us |
| Stable maximum | 244 us to 250 us |

This data is useful for understanding the end-to-end upper range. On complex
C++ stacks with dozens of frames and a maximum of 63 frames, stable P99 remains
around 200 us. libgunwinder is not just fast in a microbenchmark; it keeps real
C++ stack unwinding within a range suitable for online profiling.

### CPA bench

The following data was measured on a production C++ workload.

#### CPU

During the stable phase, DWARF unwind throughput averaged about
4.41k samples/s, with a median around 4.39k samples/s and P95 around
4.57k samples/s. The per-window average unwind latency was about 13.1 us,
with median around 12.5 us, P95 around 20.1 us, and P99 around 22.8 us.

Across roughly 1.39 million stable unwinds:

1. 77.0% completed within 16 us.
2. 98.23% completed within 64 us.
3. Only 1.77% exceeded 64 us.

![CPA bench CPU](../assets/technical-deep-dive/05-cpa-bench-cpu.png)

`pidstat` reported CPA itself at about 16.8% of one core on average, median
around 16.0%, and P95 around 20.7%. Excluding periodic flush spikes, the average
was about 16.2% of one core and P95 about 20.0%. On this resident C++ workload,
steady CPA cost was about 0.16 CPU core.

#### Memory

At the end of the run, RSS Total was about 644,208 KB, or about 629 MiB. The
core debuginfo working set was:

1. Symbol index: about 72,025 KB.
2. CFI FDE: about 26,729 KB.
3. CFI Data: about 18,104 KB.
4. Total: about 114 MiB, with a stable-phase maximum around 119 MiB.

This is the working set libgunwinder keeps to move per-frame unwinding from the
IO path to the memory path. Stack ID and string dictionary allocations added
about 132 MiB for the stack dictionary and indexes required by continuous
recording.

#### Storage

The run lasted 345 seconds. The final store directory size was about 15.31 MiB,
or about 45.4 KB/s on average.

![CPA bench storage](../assets/technical-deep-dive/06-cpa-bench-storage.png)

## Summary

libgunwinder answers the question "can online unwinding be cheap enough". It
uses minimal debuginfo loading, ELF-level sharing, and a memory-backed hot path
to turn unwinding from an offline analysis step into a resident capability.

CPA answers the question "can those unwind results be retained usefully". It
connects sampling, unwinding, aggregation, and rolling storage into a
low-overhead pipeline that keeps enough evidence for later incident analysis.

Together they form a production-oriented continuous profiling model: no waiting
for reproduction, no dependence on manual capture timing, and no shifting of all
cost to after the incident. The system leaves an explainable performance trace
while it runs.

## Appendix: CPA bench log excerpt

The following stable tail sample corresponds to the throughput, memory, RSS,
lost-event, and storage data above.

```text
[05/27 13:52:32.0465] Parse Queue Len: 0 BackTrace Time: 2023751 [FP] 0 [DWARF] 1773018 [FP_BETTER] 250733 Pid Ctx: Exist: 49 Alloc: 1048 Elf Ctx: Exist: 316 Alloc: 763
[05/27 13:52:32.0465] Detailed: Symbols Mem Size: 72025.14 KB | CFI FDE Size: 26728.83 KB | CFI Data Size 18103.99 KB
[05/27 13:52:32.0465] File Queue Len: 0 Pid Exit Queue Len: 0 Store Dir: /var/log/cpa-bench/cpa_260527_start_134646 Total Size: 15677 KB
[05/27 13:52:32.0465] Lost Events: bpf perf-buffer=0 perf mmap=0
[05/27 13:52:32.0465] RSS Anon Size: 375240 KB File Size: 268968 KB Total Size: 644208 KB
[05/27 13:52:32.0465] Ids Alloc Size : 116113 KB Str Alloc Size: 9710 KB Ids Array Size: 8192 KB Str Array Size: 1024 KB
[05/27 13:52:32.0465] Bench DWARF Unwind: count=4314 rate=4313.96/s avg=12.38 us min=1.16 us max=246.28 us
[05/27 13:52:32.0465] Bench DWARF Histogram: 1-4us=730 4-16us=2582 16-64us=921 64-256us=81
[05/27 13:52:32.0465] bpf_exec_time: [2.0-4.1](us): 7477 [4.1-8.2](us): 852254 [8.2-16.4](us): 841701 [16.4-32.8](us): 75682 [32.8-65.5](us): 35 [65.5-131.1](us): 2
```
