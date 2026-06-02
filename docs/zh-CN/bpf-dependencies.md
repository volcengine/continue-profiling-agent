# BPF 第三方依赖

[返回 README](../../README.zh-CN.md)

本文只说明当前代码树里 BPF 构建链依赖的第三方上游来源和 pin 方式。

## libbpf

- 目录：`bpf/libbpf/`
- 上游：<https://github.com/libbpf/libbpf>
- 当前保留的 checkpoint：
  - `CHECKPOINT-COMMIT`: `62c69e89e81bfbdb9a87ae3e0599dcc6aacf786b`
  - `BPF-CHECKPOINT-COMMIT`: `e7b09357453a99e6f9e74c39e9ca1363c22c0b96`

CPA 通过 git submodule 固定 `libbpf` 源码，并在构建时生成 `libbpf.a`。

## bpftool

- 目录：`bpf/bpftool/`
- 上游：<https://github.com/libbpf/bpftool>
- 当前保留的 checkpoint：
  - `CHECKPOINT-COMMIT`: `62c69e89e81bfbdb9a87ae3e0599dcc6aacf786b`
  - `BPF-CHECKPOINT-COMMIT`: `e7b09357453a99e6f9e74c39e9ca1363c22c0b96`

CPA 通过 git submodule 固定 `bpftool` 源码，并在构建时生成 skeleton 和 `min_core_btf`。

## BTFHub Archive

- 上游：<https://github.com/aquasecurity/btfhub-archive>
- 使用方式：按需提供最新上游 checkout，不在仓库内固定 pin
- 默认路径：`bpf/btfhub-archive`
- 覆盖方式：CMake 变量 `CPA_BPF_BTFHUB_ARCHIVE`

当 archive 目录存在时，构建会遍历该目录下全部 `*.btf.tar.xz` 文件，生成
`min_core_btf` 产物，不再对发行版或厂商目录做单独过滤。

## 当前约束

- `libgunwinder` 不是 BPF 第三方依赖。它位于 `libs/libgunwinder`，
  由顶层 CMake 构建流程构建为 shared object。
- 运行时默认优先使用 `/sys/kernel/btf/vmlinux`。
- 如果用户通过 `--btf_path` 提供了自定义 BTF，则优先使用该路径。
- BTF 查找键只使用当前系统的 `ID`、`VERSION_ID`、架构和 `kernel_release`。
- 如果嵌入 archive 中找不到对应条目，运行时不会再尝试厂商专用 fallback 名称。
