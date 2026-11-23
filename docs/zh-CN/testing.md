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
- `tests/cpa/test_capabilities.py`
  - 编译能力模型（`bpf/src/common/capabilities.c`）的单元测试：只探测一次，
    每个探测结果连同原因一起保存
  - `cpa capabilities` 打印每一项能力，state 合法
- `tests/cpa/test_unwind_queue.py`
  - 编译回溯队列 lane 与单样本帧缓冲的单元测试，分别以普通、ASan/UBSan、TSan
    方式运行：按进程路由、共享的准入额度与 exit 容量、exit 等待同一实例的样本、
    唤醒（只唤醒本 lane、停止时全部唤醒、lane 上第一个 exit 唤醒）、帧缓冲与
    stack map 条目语义一致
- `tests/cpa/test_unwind_workers_e2e.py`
  - 非法的 `--unwind_workers` 在任何线程启动前被拒绝；1 个和 4 个线程时，
    每个被采样进程都有用户态帧
- `tests/cpa/tools/cpa_unwind_workers.sh`
  - `TEST_CPA_PATH` 包装脚本，给每条 monitor 命令加 `--unwind_workers=4`
    （或 `$CPA_UNWIND_WORKERS`），用于以多线程跑整套测试。
    `test_cpa_multi_workload_hot_stacks_and_cpu_budget` 的预算（30 秒内平均 0.5 核）
    按单线程定，在包装脚本下预期超出：每个线程的 context 启动时都要重新加载公共库的
    调试信息（56 核机器上 4 线程整段约 0.7 核；稳态 5% 核，单线程 2.5%）
- `tests/cpa/tools/build_sanitized.sh tsan|asan OUT` 与
  `tests/cpa/tools/stress.sh CPA_BIN WORKERS SECONDS OUTDIR [monitor 参数]`
  - 以 TSan 或 ASan 构建 cpa 与 libgunwinder（`-DCPA_BPF_ENABLE_TSAN=ON` /
    `-DCPA_BPF_ENABLE_ASAN=ON`；libgunwinder 在源码目录内构建、改编译选项不会重编，
    所以从一份拷贝重新构建），再在 fork 风暴和繁忙进程下全系统采样；sanitizer
    报告数为 0 才算通过。`MIDNIGHT_IN=S`（需要 libfaketime，只能用于 ASan 构建：
    libfaketime 会破坏 TSan 的时钟拦截）让时钟在 S 秒后跨过零点，所有回溯线程
    暂停并恢复一次
- `tests/cpa/test_exit_target_parse.py`、`tests/cpa/test_exit_env.py`
  - `--exit_comm` / `--exit_pid` / `--exit_target_env_*` 的解析与报错；env 存储读真实子进程（精确与前缀匹配、取第一个设了值的名字、都没设、进程已退出、按实例、读线程），普通、ASan/UBSan、TSan 各跑一遍
- `tests/cpa/test_exit_capture_e2e.py`（`tests/cpa/exit_capture/`）
  - 1 个和 4 个回溯线程下，`exit_app` 的副本各走一条退出路径：工作线程 exit_group、leader pthread_exit 后工作线程退出或被 SIGKILL、SIGTERM、并发 exit_group（只记一条）、SIGSEGV、exit 0 和裸 SYS_exit（不记）、exec（不记）、与 coredump 同开（只有 COREDUMP）、`--exit_comm` / `--exit_pid` / `--exit_target_env_*`（启动扫描、exec、fork、不满足、读不到、4.14 exec 回退）；所有该拒绝的组合；`cpa show --list_exit`。monitor 的 Exit Capture Count 必须与记录数相等
- `tests/cpa/test_pagefault.py`
  - 编译存活集合 tracker 的单元测试（`tests/cpa/pagefault/tracker_harness.c`：分配、释放、移动、重置、迟到分配的重放、THP 拆分、采样哈希），并固定 `--pagefault` 的约定：入口只在一处选定、每个释放 hook 都必须挂上、5.4 以前以 e2e 期望的消息拒绝、在目标会话打开之前就开始接收输入
- `tests/cpa/test_pagefault_e2e.py`（`tests/cpa/pagefault/`）
  - `run_pagefault_e2e.py` 的每个用例一个测试，目标是 `pf_app`：经过每条分配和释放路径后单独一秒的存活集合（16 取 1 与精确）、启动前常驻、exec、用 `--cgroup --comm --first_match` 冷启动、主线程先退出、失败和特殊的系统调用、零页、THP、fork 写时复制、THP 部分释放、多尺寸 THP（6.8+）、`MREMAP_DONTUNMAP`；所有该拒绝的配置。只有说明原因时才跳过（没有 THP、没有多尺寸 THP）。5.4 以前每个用例都检查拒绝启动。`--unwind_workers N` 用 N 个回溯线程运行

  - 编译 `src/cpa_monitor/cpa_target.c` 的单元测试：哪些选项组合走目标集合，
    哪些保留 pid/线程名过滤，哪些被拒绝
- `tests/cpa/test_target_select_e2e.py`
  - `--comm`、`--pid` 列表、`--exe`、`--new_only`、`--children`、
    `--first_match`（运行自动结束）和 `--startup_window` 只采集它们指定的进程；
    错误组合被拒绝
- `tests/cpa/test_stack_sample_builder.py`
  - 编译 `tests/cpa/test_stack_sample_builder.c`，普通构建和
    AddressSanitizer/UndefinedBehaviorSanitizer 构建各跑一次；不需要 root
  - 样本池（首个合适的块、清零分配、销毁后的分配）
  - on-CPU 和 off-CPU 样本记录显示哪个任务、按哪个进程归类，以及交给
    libgunwinder 的进程和被采样线程
  - off-CPU、IRQ-off 样本的权重，内核线程样本和高压丢弃样本
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
