# Acknowledgements

continue-profiling-agent builds on the following open-source projects and
libraries. Please refer to each upstream project for its license and copyright
terms.

- libgunwinder: vendored stack unwinder built as a shared object for continuous
  userspace stack unwinding.
- uthash and utlist: C data-structure helper headers used by the userspace
  implementation.
- libbpf: eBPF userspace loader library used by the BPF backend.
- bpftool: used during build time to generate BPF skeletons and BTF-related
  artifacts.
- BTFHub Archive: optional source of BTF files for generating embedded
  min_core_btf artifacts.
- SOPacker: optional portable packaging tool used to bundle `cpa` and its
  dynamic library dependencies into a single executable script.
- Rust TUI ecosystem: ratatui, crossterm, unicode-width, crossbeam-channel,
  parking_lot, clap, anyhow, thiserror, zstd, memmap2, and tempfile support the
  embedded cpa_show terminal UI and tests.
- flameshow: the embedded terminal flamegraph viewer was inspired by
  <https://github.com/laixintao/flameshow>.
