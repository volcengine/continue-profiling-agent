# BPF Third-Party Dependencies

[Back to README](../../README.md)

This document describes only the third-party upstream sources and pinning model
used by the current BPF build pipeline.

## libbpf

- Directory: `bpf/libbpf/`
- Upstream: <https://github.com/libbpf/libbpf>
- Preserved checkpoints:
  - `CHECKPOINT-COMMIT`: `62c69e89e81bfbdb9a87ae3e0599dcc6aacf786b`
  - `BPF-CHECKPOINT-COMMIT`: `e7b09357453a99e6f9e74c39e9ca1363c22c0b96`

CPA pins `libbpf` as a git submodule and builds `libbpf.a` from that source
tree during the normal build.

## bpftool

- Directory: `bpf/bpftool/`
- Upstream: <https://github.com/libbpf/bpftool>
- Preserved checkpoints:
  - `CHECKPOINT-COMMIT`: `62c69e89e81bfbdb9a87ae3e0599dcc6aacf786b`
  - `BPF-CHECKPOINT-COMMIT`: `e7b09357453a99e6f9e74c39e9ca1363c22c0b96`

CPA pins `bpftool` as a git submodule and uses it to generate skeletons and
`min_core_btf` artifacts at build time.

## BTFHub Archive

- Upstream: <https://github.com/aquasecurity/btfhub-archive>
- Usage model: provide the latest upstream checkout on demand; it is not pinned
  inside this repository
- Default path: `bpf/btfhub-archive`
- Override: CMake variable `CPA_BPF_BTFHUB_ARCHIVE`

When the archive directory exists, the build scans all `*.btf.tar.xz` files
under that tree and generates `min_core_btf` from the full archive set, without
any vendor- or distro-specific filtering logic.

## Current Constraints

- `libgunwinder` is not a BPF third-party dependency. It is tracked as
  the `libs/libgunwinder` Git submodule and built as a shared object by the
  top-level CMake flow.
- At runtime CPA prefers `/sys/kernel/btf/vmlinux` when the system provides it.
- If the user passes `--btf_path`, that explicit BTF path is used instead.
- Embedded BTF lookup keys use only the current system `ID`, `VERSION_ID`,
  architecture, and `kernel_release`.
- If no matching archive entry exists, the runtime stops at that lookup result
  and does not try any vendor-specific fallback name.
