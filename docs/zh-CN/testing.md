# CPA 测试覆盖说明

本文档说明仓库当前保留的测试集、每类测试覆盖的行为，以及运行这些测试所需的环境假设。

## 默认测试集

默认开源测试集：

```bash
pytest -q tests/cpa
```

当前默认测试集包含以下文件：

- `tests/cpa/test_basic.py`
  - 基础 CLI 行为
  - BPF 能力不满足时的回退与报错
  - `--btf_path` 相关行为
  - perf backend 对 BPF 专属选项的拒绝
- `tests/cpa/test_cpa.py`
  - 默认 backend 与 perf backend 的 on-CPU 采样频率范围
- `tests/cpa/test_date_rotation.py`
  - 跨天目录轮转
  - 同一天二次启动的 `_start_` 命名
  - retention 清理
  - `show_range` 的跨天时间窗口
- `tests/cpa/test_general_cli.py`
  - 全局 help / 子命令 help / version
  - 已移除选项与未知选项的拒绝
  - `show --help` 公开文案
- `tests/cpa/test_kernel_modules.py`
  - `kworker` 内核模块样本采集
  - BPF backend 下的 `IRQOFF` 样本采集
- `tests/cpa/test_ksyms_reload.py`
  - 运行中 `kallsyms` 变化触发的 reload 行为
- `tests/cpa/test_monitor_show.py`
  - `monitor -> show` 主流程
  - `show_range`
  - `output_num`
  - 非法时间范围与损坏输入的处理
  - one-shot 默认输出文件名
- `tests/cpa/test_offcpu_probe.py`
  - `offcpu` 与 `probe` 的 normal / oneshot 行为
  - `offcpu` 的线程/进程元数据约定
- `tests/cpa/test_workload_coverage.py`
  - 多 workload 热栈覆盖
  - 默认 backend 与 perf backend 的 CPU 占用预算
  - `record_env_name`
  - `sym_go_anon`
- `tests/cpa/test_asan_e2e.py`
  - 仅在 ASan 构建下执行
  - `monitor -> show` 的 ASan 全流程 smoke，覆盖 default / perf backend

## 环境要求

默认测试集中的很多用例依赖：

- 已构建好的 `build/bin/cpa`
- root 权限
- 可加载仓库内测试模块的内核与工具链环境
- Python、gcc、cargo、go 等测试资源编译工具

其中：

- `test_kernel_modules.py` 依赖内核模块构建与 `insmod/rmmod`
- `test_ksyms_reload.py` 依赖能观测到 `kallsyms` 变化
- `test_asan_e2e.py` 依赖单独的 ASan 构建产物

## ASan 测试

ASan 构建与测试命令见 [构建指南](build.md)。

ASan 相关约束：

- `tests/cpa/test_asan_e2e.py` 是当前默认的 ASan 端到端门禁
- 多 workload 的 CPU 预算断言在 ASan 下不会作为失败条件
- ASan 下的目标是发现内存错误，不是维持 release 模式的性能阈值

## 设计原则

当前测试集只保留面向公开产品面的行为测试。

优先覆盖：

- 用户可见 CLI 行为
- `monitor/show` 主流程
- BPF 与 perf 两条采集链的真实结果
- 内核模块与 BPF 特性相关的关键行为
- `cpa_show` 的可观察输入输出契约
