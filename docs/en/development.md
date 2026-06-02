# CPA Development Guide

[Back to README](../../README.md)

## Development Principles

Prefer:

- maintaining `cpa monitor` and `cpa show`
- deleting dead code when it no longer serves current behavior
- keeping data flow explicit between capture, storage, and rendering
- documenting user-visible behavior in both English and Chinese

Avoid:

- adding unrelated feature paths
- adding broad command aliases
- growing the CLI without a clear profiling use case

## Source Layout

- `src/`: user-space CLI and runtime logic
- `src/cpa_monitor/`: monitor runtime and workers
- `src/cpa_show/`: show command, FFI bridge, and Rust viewer sources
- `bpf/`: BPF programs, loaders, and build helpers
- `tests/`: Python integration tests
- `docs/`: project documentation

## Code Style

- Use `clang-format-15` with the repository's `.clang-format` for C and header
  files.
- Prefer kernel-style, concise English comments in public headers and important
  control-flow transitions.
- Keep names aligned with the public product surface: `cpa`, `cpa_monitor`,
  `cpa_show`, `cpa_bpf`.
- Keep SPDX headers accurate in CPA-owned files.

## Working On Runtime Or BPF Paths

When changing capture or runtime behavior:

- update the relevant worker or helper documentation
- verify that storage format assumptions in `cpa show` still hold
- check whether Rust TUI loading or filtering behavior also needs an update
- keep host-side parsers defensive around malformed or partial input

## Test Strategy

The repository favors behavior-level tests around the public product surface.

Prefer tests that validate:

- main CLI behavior
- monitor/show workflows
- BPF and perf capture behavior through user-visible results
- Rust viewer behavior where it is practical to verify

See [testing.md](testing.md) for the file-by-file coverage overview.

## Documentation Workflow

If you change behavior, defaults, or architecture:

- update the relevant files under `docs/en/` and `docs/zh-CN/`
- update `README.md` and `README.zh-CN.md` when the quick-start path changes
- update `CONTRIBUTING.md` and `CONTRIBUTING.zh-CN.md` if contributor
  expectations change

## Community And Governance

- [Contributing](../../CONTRIBUTING.md)
- [Security Policy](../../SECURITY.md)
- [Code of Conduct](../../CODE_OF_CONDUCT.md)
