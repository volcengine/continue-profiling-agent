# CPA 后端与能力检查

[返回 README](../../README.zh-CN.md)

## 总览

`cpa monitor` 当前保留两条采样后端：

- `bpf`
- `perf`

但它们并不是能力对等的两套实现。当前代码里的约束是：

- `bpf` 是完整后端，支持 on-CPU 持续采样、`offcpu`、`probe`、one-shot、BPF 侧过滤，以及 IRQOFF 记录。
- `perf` 只支持 on-CPU 持续采样。

因此，CPA 在启动阶段会先做一次后端能力检查，再决定：

- 继续使用 BPF
- 打印 `WARNING` 后回退到 perf
- 或直接报错退出

## BPF 路径当前使用的内核能力

按现有代码，BPF 后端会使用这些内核 / libbpf 能力：

### BTF / CO-RE

- 需要可用的 vmlinux BTF，或者用户通过 `--btf_path` 提供的自定义 BTF。
- 采集侧依赖 CO-RE 重定位；自定义 BTF 文件如果不可读或格式无效，会在启动检查阶段被拦住。

### BPF program type

根据模式不同，会检查这些 program type：

- `BPF_PROG_TYPE_PERF_EVENT`
  - 常规 on-CPU timer 采样
- `BPF_PROG_TYPE_TRACEPOINT`
  - `sched:sched_process_exit`
  - `tracepoint:<group>:<name>` 风格的 `--probe`
- `BPF_PROG_TYPE_KPROBE`
  - `offcpu`
  - `kprobe:` / `kretprobe:` 风格的 `--probe`

### BPF map type

BPF 路径会用到：

- `BPF_MAP_TYPE_HASH`
- `BPF_MAP_TYPE_ARRAY`
- `BPF_MAP_TYPE_PERCPU_HASH`
- `BPF_MAP_TYPE_PERF_EVENT_ARRAY`

### BPF helper

当前会显式依赖：

- `bpf_get_stack`
- `bpf_perf_event_output`
- `bpf_probe_read_user`
- `bpf_probe_read_kernel`

### 具体 attach 点

- `sched:sched_process_exit`
- `finish_task_switch`（off-CPU）
- 用户通过 `--probe` 指定的目标

也就是说，CPA 不只是“能 load 一个 BPF 程序”就算满足，而是要连同当前模式真正会触发的 helper、program type、attach target 一起检查。

## 启动时的检查策略

`cpa monitor` 在 runtime 启动前会做预检。当前策略如下：

### 1. 先判断用户是否显式要求 `perf`

如果用户指定了 `--backend=perf`，但同时又开启了 perf 不支持的选项，CPA 会直接报错。

当前会被拒绝的组合包括：

- `--oneshot`
- `--offcpu`
- `--probe`
- `--pid`
- `--comm`
- `--kernel_stack`
- 非默认 `--stack_size`

报错原则是：不要让不生效的参数静默混进 perf 路径。

### 2. 如果当前请求是 BPF

CPA 会检查：

- BTF 是否可用
- 当前模式需要的 program type / map type / helper 是否可用
- attach target 是否真实存在

### 3. 根据模式决定回退还是报错

不是所有 BPF 失败都能自动回退到 perf。当前矩阵如下。

## 回退矩阵

### 可以回退到 perf 的情况

只有“纯 on-CPU 持续采样”这一类请求可以回退。也就是：

- `backend=bpf`
- 没开 `--oneshot`
- 没开 `--offcpu`
- 没开 `--probe`
- 没设置 `--pid`
- 没设置 `--comm`
- 没开 `--kernel_stack`
- 没把 `--stack_size` 改成非默认值

如果这时 BPF 不满足，CPA 会：

- 打印 `WARNING`
- 明确说明失败原因
- 自动改走 perf
- 明确提示 perf 没有 IRQOFF 记录

### 不允许回退的情况

以下模式一旦 BPF 不满足，CPA 会直接报错退出：

- `--oneshot`
- `--offcpu`
- `--probe`
- `--pid`
- `--comm`
- `--kernel_stack`
- 非默认 `--stack_size`

原因很直接：这些能力要么完全是 BPF 专属，要么 perf 路径不能等价保留语义。

## perf 后端的真实能力边界

当前 perf 后端只承诺：

- on-CPU 持续采样
- 写出可被 `cpa show` / `cpa_show` 直接读取的持续 store 目录

当前 perf 后端不提供：

- `offcpu`
- `probe`
- one-shot
- BPF 侧 `pid/comm/kernel_stack` 过滤
- 自定义 `stack_size` 语义
- IRQOFF 记录

另外，当前 perf 路径的 metadata 中 `cgroup_id` 也不像 BPF 路径那样来自内核采样点，因此该字段可能为 `0`。

## WARNING 和报错口径

### 自动回退时

CPA 会输出类似下面的 warning：

```text
WARNING: BPF capability check failed: <reason>. Falling back to perf backend; perf only supports on-cpu continuous profiling and provides no IRQOFF records.
```

### 必须失败时

如果当前请求依赖 BPF 专属能力，则会输出类似：

```text
BPF capability check failed: <reason>. Requested mode requires BPF backend and cannot fall back to perf; perf backend only supports on-cpu continuous profiling.
```

## 使用建议

### 什么时候建议显式写 `--backend=bpf`

- 你明确依赖 `offcpu`
- 你明确依赖 `--probe`
- 你要 one-shot
- 你要 BPF 侧过滤或内核栈-only 语义
- 你关心 IRQOFF 记录

### 什么时候可以接受自动回退

- 你只需要“机器级 / 服务级”的 on-CPU 持续趋势
- 你只关心 store 能继续产出、`cpa show` 能继续读
- 你接受这次采集中没有 IRQOFF 记录，且 cgroup 维度可能不完整

## 背后的设计取舍

CPA 保留 perf 回退的原因，不是因为它和 BPF 等价，而是因为：

- 对“纯 on-CPU 持续采样”来说，perf 仍然能产出可用的连续 store
- 出问题时，用户至少还能先拿到一份 trend / flamegraph，而不是完全失去采样

但 CPA 不把这种回退扩大到 `offcpu`、`probe`、one-shot 或 BPF 侧过滤，是因为那样会把“静默语义变化”带进生产，这比直接失败更危险。
