# Contributing

[中文版本](CONTRIBUTING.zh-CN.md)

## Repository Contents

This repository contains:

- `cpa monitor`
- `cpa show`
- the embedded Rust `cpa_show` viewer
- the profiling runtime, storage format, and required BPF programs

## Before You Change Code

- Read [README.md](README.md) and the docs under `docs/en/`.
- Keep the public product name consistent: `continue-profiling-agent` / `cpa`.
- Preserve the embedded `cpa_show` path used by `cpa show --use_cui`.

## Development Environment

Recommended prerequisites:

- Linux with eBPF CO-RE support
- `cmake >= 3.18`
- `clang`, `llvm-strip`, `llvm-objdump`
- `python3`
- `cargo`
- `make`
- development libraries for `elf`, `dw`, `zstd`, `crypto`, and `iberty`

Build locally with:

```bash
cmake -S . -B build
cmake --build build -j
```

## Tests

Run the main open-source test set with:

```bash
pytest -q tests/cpa
```

See [docs/en/testing.md](docs/en/testing.md) for coverage details.

Useful additional checks:

```bash
cargo test --manifest-path src/cpa_show/rust/Cargo.toml
cmake --build build -j
```

Many integration tests require root privileges and a kernel/toolchain capable of
loading the bundled fixture modules.

## Code Expectations

- Keep the public CLI surface consistent.
- Avoid reintroducing aliases unless they have clear user value.
- Prefer exact input validation over silent fallback behavior.
- Use `clang-format-15` with the repository's kernel-style `.clang-format` for
  C and header changes.
- Add concise English comments in public headers and non-obvious code paths.
- Keep SPDX headers accurate for CPA-owned files.

## Documentation Expectations

- Update English and Chinese user-facing docs when behavior, defaults, or build
  requirements change.
- Keep architecture and usage docs aligned with the current implementation.
- If you change `cpa show --use_cui`, also check the component docs under
  `src/cpa_show/`.

## Pull Requests

Include the following in each change:

- the user-visible behavior change
- build and test commands used for validation
- kernel, privilege, or environment assumptions
- any storage format, CLI, or documentation impact

## Community

- [Security Policy](SECURITY.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
