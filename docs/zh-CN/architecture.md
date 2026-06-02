# CPA 架构说明

[返回 README](../../README.zh-CN.md)

## 总览

`continue-profiling-agent` 由两条主要命令组成：

1. `cpa monitor` 负责采样并写出持久化 profile 目录。
2. `cpa show` 负责读取这些目录，并输出 flamegraph 或进入内嵌 Rust TUI。

## 高层数据流

```text
kernel 事件 / perf sample
          |
          v
   BPF 或 perf 采集后端
          |
          v
      CPA runtime workers
          |
          v
   共享的 cli_stackmap 状态
          |
          v
      磁盘上的 profile 目录
          |
          v
  cpa show / 内嵌 cpa_show
```

## 主要组件

## CLI 层

顶层 CLI 入口主要位于 `src/`：

- `cli.c`：根命令分发
- `cpa_monitor/`：`cpa monitor`
- `cpa_show/`：`cpa show` 以及到 Rust 的 FFI bridge
- `cli_*` helper：stackmap 解析、目录管理、metadata、配置、队列、zstd 等辅助逻辑

当前对外子命令为：

- `cpa monitor`
- `cpa show`

## Runtime 层

`cpa monitor` 使用基于 worker 的 runtime。每个 worker 可以实现
`init`、`timer`、`main_worker`、`pause`、`restore`、`destroy` 等生命周期钩子。

worker 集覆盖：

- BPF 采集
- perf 采集
- unwind 与符号化
- 环境变量过滤支持
- no-BPF unwind 元数据维护
- 持续目录轮转
- one-shot 输出
- 本地状态统计
- debug dump 路径

runtime 统一持有共享 `cli_stackmap`，负责 worker 启动顺序、周期回调，以及在缓存或存储超限时执行 restart 流程。

worker 细节可参考 [src/cpa_monitor/README.md](../../src/cpa_monitor/README.md)。

## 采集后端

CPA 保留两条 on-CPU 采样后端：

- BPF 后端
  - CO-RE BPF 程序在 `bpf/` 下构建。
  - host 侧 loader 与 event parser 位于 `bpf/src/`。
  - 内核栈通过 `bpf_get_stack()` 采集，随后在用户态做符号化。
- perf 后端
  - 当不使用 BPF 采样时，作为替代采样源保留。

可选采集模式：

- off-CPU 采集
- `--probe` 触发的内核栈采集

## 存储格式

`cpa monitor` 会在 `store_dir` 下按时间桶写出 profile 目录。关键文件包括：

- `conf`：运行时配置快照
- `strmap`：字符串表，用于符号和元数据还原
- `idsmap`：紧凑的栈标识映射
- `stack.bin`：按时间顺序组织的栈样本和 record 边界
- `cpa show` 使用的解压或派生文件

这里的目录格式，而不是在线 RPC 协议，是采集端和展示端之间最稳定的接口。

详细格式说明见：

- [存储格式说明](store-format.md)
- [后端与能力检查](backend-modes.md)

## cpa show 与 cpa_show

`cpa show` 是用户可见的数据查看命令，支持：

- 时间范围选择
- 基于 metadata 的过滤
- flamegraph 导出
- 选定时间范围的 split 导出
- 通过 `--use_cui` 打开内嵌 Rust TUI

`cpa_show` 以内嵌 Rust 静态库形式构建，并通过 C 侧 FFI bridge 被调用。

Rust 侧按 loader 和 UI-facing profile model 拆分，这样后续即使存储格式演进，也尽量不影响终端 UI 逻辑。

可参考：

- [src/cpa_show/README.md](../../src/cpa_show/README.md)
- [src/cpa_show/doc/cpa_show.md](../../src/cpa_show/doc/cpa_show.md)

## 构建结构

关键构建关系：

- 顶层 CMake 驱动整体构建
- `cmake/cpa.cmake` 负责组装 `cpa` 可执行文件
- `bpf/` 负责 BPF 对象、loader 和生成产物
- `libs/libgunwinder` 通过 Git submodule 跟踪，并从源码构建；
  `libgunwinder.so` 会被复制到 `cpa` 旁边，并通过 `$ORIGIN` 动态链接
- `src/cpa_show/rust/` 通过 Cargo 构建为静态库

BPF host 侧代码通过 `cpa_bpf_core` object target 直接编入主程序，而不是再对外提供一个独立库。
