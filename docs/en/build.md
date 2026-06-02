# CPA Build Guide

[Back to README](../../README.md)

## Host Requirements

CPA is intended for Linux systems with eBPF CO-RE support.

Required tools:

- `cmake >= 3.10`
- `clang`
- `llvm-strip`
- `llvm-objdump`
- `python3`
- `cargo`
- `make`

Required libraries:

- `libelf`
- `libdw`
- `libzstd`
- `libcrypto`
- `libiberty`

On Ubuntu 24.04, install the build dependencies with:

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  autoconf automake binutils-dev build-essential clang-18 cmake curl git \
  libdw-dev libelf-dev libiberty-dev libssl-dev libtool libzstd-dev \
  llvm-18 make pkg-config python3 zlib1g-dev zstd
```

Then configure with `-DCPA_BPF_LLVM_VERSION=18`.

Practical requirements:

- a kernel with usable BTF/CO-RE support for the BPF backend
- permission to run BPF and perf collection
- a Rust toolchain for the embedded `cpa_show` static library
- the `libs/libgunwinder` submodule initialized from GitHub

See [docs/en/bpf-dependencies.md](bpf-dependencies.md) for the third-party BPF
dependency sources and preserved checkpoints.

## Configure And Build

Initialize the BPF-related submodules after the first clone:

```bash
git submodule update --init --recursive
```

Standard build:

```bash
cmake -S . -B build
cmake --build build -j
```

Main output:

- `build/bin/cpa`

During the normal build, CMake invokes the `lib/libgunwinder.so` Makefile
target under `libs/libgunwinder`, copies the generated shared object next to
`build/bin/cpa`, and links `cpa` dynamically with an `$ORIGIN` runtime search
path. No separate `libgunwinder` installation is required for a source-tree
build.

ASan build:

```bash
cmake -S . -B build-asan -DCPA_BPF_ENABLE_ASAN=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build-asan -j
```

ASan output:

- `build-asan/bin/cpa`

Portable packed artifact:

```bash
cmake --build build -j --target cpa_portable
```

- `build/bin/cpa_portable`

`cpa_portable` is produced through
[SOPacker](https://github.com/XinShuichen/sopacker). By default the first build
of that target clones the upstream repository into the build directory on
demand. If you already have a local checkout, configure with:

```bash
cmake -S . -B build -DCPA_BPF_SOPACKER_DIR=/path/to/sopacker
```

This target packages the dynamically linked executable and its dependent shared
libraries into a single executable script. It is not a static link of
`libgunwinder`.

Generated build artifacts:

- BPF-generated files under `build/generated/`
- Rust static library under `src/cpa_show/rust/target/release/`

If you want to generate embedded `min_core_btf` artifacts at build time:

```bash
git clone --depth 1 https://github.com/aquasecurity/btfhub-archive bpf/btfhub-archive
cmake -S . -B build
cmake --build build -j
```

The build automatically embeds the archive when `bpf/btfhub-archive` exists.
You can also point CMake at another checkout with
`-DCPA_BPF_BTFHUB_ARCHIVE=/path/to/btfhub-archive`.

## Rebuild From Scratch

When changing build-system, BPF, or Rust integration details, a clean rebuild is
often faster than chasing stale artifacts:

```bash
rm -rf build
cmake -S . -B build
cmake --build build -j
```

If you need to force a clean Rust rebuild:

```bash
rm -rf src/cpa_show/rust/target
cmake --build build -j
```

## Running Tests

Primary Python test set:

```bash
pytest -q tests/cpa
```

ASan end-to-end smoke:

```bash
TEST_CPA_PATH=$PWD/build-asan/bin/cpa \
TEST_CPA_ASAN=1 \
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
pytest -q tests/cpa/test_asan_e2e.py
```

Notes:

- `tests/cpa/test_asan_e2e.py` covers the `monitor -> show` main path
- `libfaketime`-based date-rotation tests are skipped under ASan
- CPU-budget and performance assertions are not used as ASan quality gates

Rust tests for the embedded viewer:

```bash
cargo test --manifest-path src/cpa_show/rust/Cargo.toml
```

Many integration tests require:

- root privileges
- a kernel and toolchain that can load the bundled fixture modules
- a successful prior build of `build/bin/cpa`

## Common Build Issues

Missing Cargo:

- `cpa_show` is required by this repository.
- `cmake/cpa.cmake` will fail the build if `cargo` is not available.

Missing system libraries:

- The build expects `elf`, `dw`, `zstd`, `crypto`, and `iberty`.
- If CMake cannot find them, inspect your system library paths or set
  `CMAKE_LIBRARY_PATH`.

BTF or kernel mismatch:

- The BPF backend depends on the target kernel and BTF availability.
- By default CPA uses `/sys/kernel/btf/vmlinux` when the system provides it.
- Use `--btf_path` at runtime if you need to override the BTF input.

Privilege problems:

- `cpa monitor` and most integration tests need enough privilege to open perf
  events, load BPF programs, and inspect target processes.
