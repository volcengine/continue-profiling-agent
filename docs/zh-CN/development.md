# CPA 开发指南

[返回 README](../../README.zh-CN.md)

## 开发原则

优先做的事情：

- 维护 `cpa monitor` 和 `cpa show`
- 清理无实际用途的死代码
- 让采集、存储和展示之间的数据流尽量直接
- 对用户可见的变化同步维护中英文文档

应避免的事情：

- 引入无关功能
- 长期保留大面积 alias
- 在没有明确 profiling 价值时扩张 CLI 面

## 源码布局

- `src/`：用户态 CLI 与 runtime 逻辑
- `src/cpa_monitor/`：monitor runtime 和 workers
- `src/cpa_show/`：show 命令、FFI bridge 与 Rust viewer 源码
- `bpf/`：BPF 程序、loader 与构建辅助
- `tests/`：Python 集成测试
- `docs/`：项目文档

## 代码风格

- C 和头文件使用仓库内 `.clang-format`，建议执行 `clang-format-15`
- 公开头文件和关键控制流路径使用简洁的英文 kernel 风格注释
- 命名与对外产品面保持一致：`cpa`、`cpa_monitor`、`cpa_show`、`cpa_bpf`
- CPA 自有文件中的 SPDX 头需要保持准确

## 修改 Runtime 或 BPF 路径时

改动采集链或 runtime 行为时，建议同步检查：

- 对应 worker 或 helper 文档是否需要更新
- `cpa show` 对存储格式的假设是否仍成立
- Rust TUI 的加载和过滤逻辑是否需要跟进
- host 侧 parser 是否对损坏或部分写入的数据足够防御

## 测试策略

仓库更偏向围绕公开产品面的行为级测试。

建议保留或新增的测试：

- 核心 CLI 行为
- monitor/show 主流程
- 通过用户可见结果验证 BPF 和 perf 采集行为
- 能实际验证到的 Rust viewer 行为

测试文件与覆盖范围总览见 [testing.md](testing.md)。

## 文档维护

如果改动了行为、默认值或架构：

- 同时更新 `docs/en/` 和 `docs/zh-CN/`
- 快速开始路径变化时同步更新 `README.md` 和 `README.zh-CN.md`
- 如果贡献者约束变化，再更新 `CONTRIBUTING.md` 和 `CONTRIBUTING.zh-CN.md`

## 社区与治理

- [贡献指南](../../CONTRIBUTING.zh-CN.md)
- [安全策略](../../SECURITY.md)
- [行为准则](../../CODE_OF_CONDUCT.md)
