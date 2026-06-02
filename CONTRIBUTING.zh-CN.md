# 贡献指南

[English](CONTRIBUTING.md)

## 仓库内容

本仓库主要包含这些部分：

- `cpa monitor`
- `cpa show`
- 内嵌 Rust `cpa_show` 查看器
- profiling runtime、存储格式以及所需的 BPF 程序

## 修改代码前

- 先阅读 [README.zh-CN.md](README.zh-CN.md) 以及 `docs/zh-CN/` 下的文档。
- 对外产品名统一使用 `continue-profiling-agent` / `cpa`。
- 保留 `cpa show --use_cui` 对内嵌 `cpa_show` 的调用路径。

## 开发环境

推荐前置条件：

- 支持 eBPF CO-RE 的 Linux 环境
- `cmake >= 3.18`
- `clang`、`llvm-strip`、`llvm-objdump`
- `python3`
- `cargo`
- `make`
- `elf`、`dw`、`zstd`、`crypto`、`iberty` 对应的开发库

本地构建：

```bash
cmake -S . -B build
cmake --build build -j
```

## 测试

开源默认测试集：

```bash
pytest -q tests/cpa
```

测试覆盖范围说明见 [docs/zh-CN/testing.md](docs/zh-CN/testing.md)。

建议同时执行：

```bash
cargo test --manifest-path src/cpa_show/rust/Cargo.toml
cmake --build build -j
```

很多集成测试依赖 root 权限，以及能加载仓库内测试模块的内核和工具链环境。

## 代码要求

- CLI 对外能力要保持一致，不要引入无明确用途的额外入口。
- 不要添加无明确用途的额外行为分支。
- 输入校验要明确，不要静默兜底成错误的默认行为。
- C 和头文件改动使用仓库内 kernel 风格 `.clang-format`，建议运行
  `clang-format-15`。
- 在公开头文件和不直观的复杂路径上补充简洁英文注释。
- CPA 自有代码的 SPDX 头要准确。

## 文档要求

- 行为、默认值或构建依赖变更时，同时更新英文和中文文档。
- 架构文档和使用文档要与当前实现保持一致。
- 如果修改了 `cpa show --use_cui` 相关逻辑，也要同步检查
  `src/cpa_show/` 下的组件文档。

## 提交说明

每个改动至少应说明：

- 用户可见行为变化
- 用于验证的构建和测试命令
- 依赖的内核、权限或环境假设
- 是否影响存储格式、CLI 或文档

## 社区与治理

- [安全策略](SECURITY.md)
- [行为准则](CODE_OF_CONDUCT.md)
