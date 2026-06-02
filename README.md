# continue-profiling-agent

[中文文档](README.zh-CN.md)

`continue-profiling-agent` (`cpa`) is a Linux continuous profiling agent built
to keep performance evidence available after an incident has already happened.
It continuously records ultra-low-overhead profiling history on production
hosts, so engineers can inspect the exact time window later instead of waiting
for the issue to reproduce.

![CPA TUI](docs/assets/technical-deep-dive/02-cpa-tui.png)

## Why CPA

- Ultra-low overhead: with the highly optimized libgunwinder, CPA can
  continuously record whole-machine, per-second flamegraphs for all processes
  at very low and often unnoticeable cost.
- Always-on evidence: CPA keeps recent second-level profiling history on the
  host and rotates it by policy.
- No application intrusion: CPA does not modify, inject into, or restart user
  processes, so profiling can stay resident without changing application
  behavior.
- Practical incident workflow: `cpa show` can export flamegraph data or open an
  interactive TUI to jump to the affected wall-clock time.

## Commands

CPA has two primary commands:

- `cpa monitor`: collect and persist profile data
- `cpa show`: inspect stored data as a flamegraph or in the embedded Rust TUI

## What CPA Contains

- continuous on-CPU profiling through BPF or perf backends
- off-CPU collection
- probe-triggered stack capture
- persistent store rotation under `store_dir`
- flamegraph export through `cpa show`
- embedded Rust TUI through `cpa show --use_cui`

## Architecture At A Glance

CPA has four major layers:

1. CLI layer
   - `cpa monitor` parses runtime and filtering options.
   - `cpa show` reads stored profile data and renders either a flamegraph or the
     embedded TUI.
2. Profiling runtime
   - The runtime is organized around workers for capture, unwind, storage
     rotation, local statistics, and debug paths.
3. BPF and perf capture backends
   - BPF capture uses CO-RE programs and host-side loaders under `bpf/`.
   - Perf capture remains available as the alternate sampling backend.
4. Storage and viewer
   - `cpa monitor` writes a directory containing `conf`, `strmap`, `idsmap`,
     `stack.bin`, and related metadata.
   - `cpa show` and the Rust `cpa_show` library consume that directory.

See the detailed architecture guide in
[docs/en/architecture.md](docs/en/architecture.md).

For the on-disk format and backend fallback rules, see:

- [中文：存储格式说明](docs/zh-CN/store-format.md)
- [中文：后端与能力检查](docs/zh-CN/backend-modes.md)
- [中文：BPF 第三方依赖](docs/zh-CN/bpf-dependencies.md)
- [English: Store Format](docs/en/store-format.md)
- [English: Backends and Capability Checks](docs/en/backend-modes.md)
- [English: BPF Third-Party Dependencies](docs/en/bpf-dependencies.md)
- [English: Technical Deep Dive](docs/en/technical-deep-dive.md)

## Build

Prerequisites:

- Linux with eBPF CO-RE support
- `cmake >= 3.10`
- `clang`, `llvm-strip`, `llvm-objdump`
- `python3`
- `cargo`
- `make`
- development libraries for `elf`, `dw`, `zstd`, `crypto`, and `iberty`
- the `libs/libgunwinder` submodule initialized from GitHub

Build from source:

```bash
git submodule update --init --recursive
cmake -S . -B build
cmake --build build -j
```

The main executable is generated at `build/bin/cpa`.

To generate the portable single-file distribution artifact through
[SOPacker](https://github.com/XinShuichen/sopacker), run:

```bash
cmake --build build -j --target cpa_portable
```

That target produces `build/bin/cpa_portable`. It packages the dynamically
linked `cpa` executable and its dependent shared libraries; it is not a static
link of LGPL components. To reuse an existing local
checkout, point CMake at it with
`-DCPA_BPF_SOPACKER_DIR=/path/to/sopacker`.

The portable artifact is a self-extracting script intended for distribution to
hosts that may not have `libgunwinder` installed. It keeps CPA dynamically
linked, so `libgunwinder.so` can still be replaced when validating a different
LGPL build or deploying a patched unwinder.

To replace the bundled `libgunwinder.so` in a `cpa_portable` artifact:

```bash
# Extract once and run a cheap command.
./cpa_portable version

# The generated script records its extraction directory near the top.
tmpdir=$(sed -n 's/^tempdir=//p' ./cpa_portable | head -n1)

# Replace the unpacked shared object. The replacement must be ABI-compatible
# and should use the same SONAME, libgunwinder.so.
cp /path/to/libgunwinder.so "$tmpdir/libgunwinder.so"

# Run the portable artifact again; SOPacker reuses the existing extraction
# directory when the unpacked cpa binary still matches the embedded checksum.
./cpa_portable version
```

For one-off testing, an explicit preload also works and avoids changing the
temporary directory:

```bash
LD_PRELOAD=/path/to/libgunwinder.so ./cpa_portable version
```

If `/tmp` is cleaned or the portable artifact changes, repeat the extraction and
replacement steps.

See [docs/en/build.md](docs/en/build.md) for a complete build and test guide.

## libgunwinder CFI Benchmark

`libgunwinder` includes `cfi_bench`, a focused microbenchmark for the DWARF CFI
frame evaluator. The benchmark below was measured on 2026-06-01 on an
Intel(R) Xeon(R) Platinum 8336C CPU @ 2.30GHz, Linux 5.15.152, GCC 8.3.0.
Each row is the median of three runs pinned
to CPU0:

```bash
taskset -c 0 libs/libgunwinder/bin/cfi_bench \
  --frames 20000000 --set-size <N> --warmup 10000
```

| Working set | CFI frames/s | Avg ns/frame | P50 ns | P99 ns | 16-frame samples/s | 32-frame samples/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | 11,998,307 | 83.35 | 70.11 | 167.27 | 749,894 | 374,947 |
| 1,000 | 4,227,484 | 236.55 | 228.41 | 327.33 | 264,218 | 132,109 |
| 10,000 | 1,353,664 | 738.74 | 737.73 | 862.48 | 84,604 | 42,302 |

The sample-rate columns are theoretical values calculated as CFI frames per
second divided by average stack depth. End-to-end CPA throughput also includes
sampling, queueing, symbol formatting, store writes, and cold ELF/CFI loads.

## Quick Start

Install CPA from the latest release and start the systemd service:

```bash
curl -fsSL https://raw.githubusercontent.com/volcengine/continue-profiling-agent/main/tools/install_cpa.sh | sudo bash
```

Check that the service is running:

```bash
sudo systemctl status cpa.service
cpa version
```

CPA stores profiling data under `/var/log/cpa` by default. Print the available
time range from a stored directory:

```bash
cpa show --read /var/log/cpa/cpa_YYMMDD --show_range 1
```

Export a flamegraph profile:

```bash
cpa show --read /var/log/cpa/cpa_YYMMDD --output_prof cpa.prof
```

Open the embedded Rust TUI:

```bash
cpa show --read /var/log/cpa/cpa_YYMMDD --use_cui
```

Uninstall CPA while preserving profiling data:

```bash
curl -fsSL https://raw.githubusercontent.com/volcengine/continue-profiling-agent/main/tools/install_cpa.sh | sudo bash -s -- --uninstall
```

See [docs/en/usage.md](docs/en/usage.md) for more examples.

## Deployment

After a GitHub release is published, install the portable Linux x86_64 package
with:

```bash
curl -fsSL https://raw.githubusercontent.com/volcengine/continue-profiling-agent/main/tools/install_cpa.sh | sudo bash
```

To install a specific release tag:

```bash
curl -fsSL https://raw.githubusercontent.com/volcengine/continue-profiling-agent/main/tools/install_cpa.sh | sudo bash -s -- --version v1.0.0
```

For a locally built systemd-managed installation, use the deployment helper:

```bash
sudo tools/deploy_cpa.sh --binary build/bin/cpa
```

On hosts without `/sys/kernel/btf/vmlinux`, generate a matching detached BTF
with `pahole` and pass it explicitly:

```bash
sudo mkdir -p /etc/cpa
sudo pahole --btf_encode_detached=/etc/cpa/vmlinux.btf \
  /usr/lib/debug/boot/vmlinux-$(uname -r)
sudo tools/deploy_cpa.sh --binary build/bin/cpa --btf /etc/cpa/vmlinux.btf
```

The helper creates `/var/log/cpa`, writes `/etc/cpa/cpa.conf`, installs a
`cpa.service` systemd unit, and starts CPA at 49 Hz by default. See
[docs/en/deploy.md](docs/en/deploy.md) for the full deployment guide.

## Option Reference

Shared generic options:

- `--help, -h`: print help.
- `--verbose, -v`: enable verbose CLI logging.
- `--config, -C <FILE>`: override options from a config file using `{arg_name}: {arg_val}` entries.
- `--btf_path, -b <PATH>`: override the custom BTF path used by the BPF backend. Startup preflight rejects unreadable or invalid BTF objects.
- `--duration, -d <SEC>`: stop `cpa monitor` after the given number of seconds.

`cpa monitor` options:

- `--store_dir, -s <DIR>`: root directory for continuous CPA stores.
- `--backend <bpf|perf>`: select the sampling backend. `perf` only supports continuous on-CPU profiling; plain continuous on-CPU requests may fall back to `perf` when BPF is unavailable.
- `--freq, -F <HZ>`: sampling frequency.
- `--record_interval, -r <SEC>`: store rotation and query granularity.
- `--persistent_day, -P <DAYS>`: retain only the latest N days of continuous stores.
- `--oneshot`: write a single flamegraph profile instead of rotating store directories. Requires the BPF backend.
- `--output_prof, -o <PATH>`: output path for one-shot mode. Default: `cpa.prof`.
- `--pid, -p <PID>`: capture one target pid. Requires the BPF backend.
- `--comm, -n <NAME>`: capture tasks matching one comm/group-comm name. Requires the BPF backend.
- `--kernel_stack, -K`: capture kernel-space stacks only. Requires the BPF backend.
- `--offcpu, -u`: collect off-CPU samples. Only valid on the BPF backend.
- `--probe <SPEC>`: capture stacks only when a probe fires, using bpftrace-style syntax such as `kprobe:try_to_free_pages`.
- `--disable_sym, -S`: disable symbol parsing and keep raw addresses where applicable.
- `--include_full_path`: keep full file paths in rendered frames where available.
- `--strip_name_disable`: disable Go symbol-name stripping.
- `--record_env_name, -R <LIST>`: record these env keys into metadata so `cpa show` can filter on them.
- `--parse_env_values, -V <LIST>`: only unwind user stacks for processes whose recorded env values match this list.
- `--max_queue_size, -m <N>`: maximum in-memory stack event queue length before backpressure.
- `--stack_size <BYTES>`: BPF backend user-stack capture buffer size. Must be 4K-aligned and within `[4096, 65536]`. The perf backend does not support custom stack-size semantics.
- `--max_cache_size_mb <MB>`: restart monitor when symbol/debug cache usage exceeds this limit.
- `--max_store_size_mb <MB>`: restart monitor and trim old stores when store usage exceeds this limit.
- `--log_print_cycles <N>`: print local runtime statistics every N timer cycles.
- `--bench`: print per-stat-interval final-DWARF-path benchmark statistics, including measured sample count, actual unwind rate, average/min/max latency, and fixed latency buckets. `FP_BETTER` samples are excluded. Cold symbol/CFI loading can appear in the first few intervals.
- `--debug_option <PID,FREQ,PATH>`: debug capture override in `{pid},{sample_freq},{dump_path}` form.

`cpa show` options:

- `--read, -r <DIR>`: input CPA profile directory.
- `--starttime, -B <HH:MM:SS>`: absolute start time in the stored record timeline.
- `--endtime, -E <HH:MM:SS>`: absolute end time in the stored record timeline.
- `--output_num, -n <N>`: export N consecutive records from the selected point. Must be a positive integer.
- `--output_prof, -o <PATH>`: flamegraph output path. Without explicit time
  options, export starts from the first matching record. If omitted, CPA
  generates `cpa_<time>_<n>.prof`.
- `--show_range, -p`: print the available record time range and exit.
- `--use_cui, -G`: open the embedded Rust `cpa_show` terminal UI.
- `--use_cache, -u`: reuse files under `decompressed/` instead of re-decompressing them.
- `--split_path <DIR>`: export the selected time range as raw split files into this directory.
- `--show_thread_name, -S`: include thread names in flamegraph output.
- `--no_pid, -P`: omit pid suffixes from metadata labels.
- `--no_env, -V`: omit env labels from metadata labels.
- `--show_raw, -R`: render raw metadata entries instead of formatted CPA labels.
- `--target_pid <PID>`: filter to one pid.
- `--target_comm <NAME>`: filter to one process group comm.
- `--target_env <VALUE>`: filter to one recorded env value.
- `--target_cgroup_id <ID>`: filter to one cgroup ID.
- `--target_cpu <CPUSET>`: filter to CPUs in a standard CPU-set expression such as `1-3,5,7-9`.

## Documentation

English:

- [Architecture](docs/en/architecture.md)
- [Technical Deep Dive](docs/en/technical-deep-dive.md)
- [Store Format](docs/en/store-format.md)
- [Backends and Capability Checks](docs/en/backend-modes.md)
- [BPF Third-Party Dependencies](docs/en/bpf-dependencies.md)
- [Usage Guide](docs/en/usage.md)
- [Deployment Guide](docs/en/deploy.md)
- [Build Guide](docs/en/build.md)
- [Test Coverage Guide](docs/en/testing.md)
- [Development Guide](docs/en/development.md)
- [Contributing](CONTRIBUTING.md)

中文:

- [架构说明](docs/zh-CN/architecture.md)
- [技术解读](docs/zh-CN/technical-deep-dive.md)
- [存储格式说明](docs/zh-CN/store-format.md)
- [后端与能力检查](docs/zh-CN/backend-modes.md)
- [BPF 第三方依赖](docs/zh-CN/bpf-dependencies.md)
- [使用手册](docs/zh-CN/usage.md)
- [部署指南](docs/zh-CN/deploy.md)
- [构建指南](docs/zh-CN/build.md)
- [测试覆盖说明](docs/zh-CN/testing.md)
- [开发指南](docs/zh-CN/development.md)
- [贡献指南](CONTRIBUTING.zh-CN.md)

Component docs:

- [CPA Monitor runtime](src/cpa_monitor/README.md)
- [cpa_show overview](src/cpa_show/README.md)
- [cpa_show user guide (English)](src/cpa_show/doc/cpa_show.en.md)
- [cpa_show 用户手册](src/cpa_show/doc/cpa_show.md)

## Test

The repository contains Python-based integration tests under `tests/`.

```bash
pytest -q tests/cpa
```

See [docs/en/testing.md](docs/en/testing.md) for suite coverage details.

Many tests require:

- a built `build/bin/cpa`
- root privileges
- a kernel and toolchain that can load the bundled fixture modules

## Repository Layout

- `src/`: user-space CLI, `cpa monitor`, `cpa show`, and the `cpa_show` Rust
  integration
- `bpf/`: BPF programs, host-side loaders, skeleton generation,
  `libbpf` / `bpftool` submodules, and build helpers
- `tests/`: unit and integration tests
- `docs/`: English and Chinese project documentation

## Project Notes

- `cpa_show` is built as an embedded Rust library for `cpa show --use_cui`; it
  is not shipped as a standalone executable in this repository.
- `libgunwinder` is tracked as the `libs/libgunwinder` submodule. The CMake
  build invokes its Makefile, copies `libgunwinder.so` next to `build/bin/cpa`,
  and links `cpa` dynamically with an `$ORIGIN` runtime search path.
- The default storage directory is `/var/log/cpa`.
- The default one-shot output name is `cpa.prof`.

## Community

- [Contributing](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Acknowledgements](ACKNOWLEDGEMENTS.md)

## License

This repository is licensed under the Apache License 2.0. See
[LICENSE](LICENSE).
