# CPA 存储格式说明

[返回 README](../../README.zh-CN.md)

## 范围

CPA 当前有两类最终产物：

- 持续采集目录：由 `cpa monitor` 常规模式写入，供 `cpa show` 和内嵌 `cpa_show` TUI 读取。
- one-shot flamegraph：由 `cpa monitor --oneshot` 直接输出折叠栈文本文件，通常命名为 `cpa.prof`。

本页重点说明第一类，也就是持续采集目录的磁盘格式。

## 目录结构

一个典型的持续采集目录通常类似：

```text
cpa_YYMMDD/
├── conf
├── strmap
├── idsmap
├── stack.bin
└── decompressed/        # 仅由 cpa show 按需生成的缓存目录
```

说明：

- `conf` 是明文配置快照。
- `strmap`、`idsmap`、`stack.bin` 都是 zstd 压缩文件。
- `decompressed/` 不是采集端正式产物，而是 `cpa show` 为加速重读生成的解压缓存。

## `conf`

`conf` 由 `cpa monitor` 在创建新 store 目录时写入，格式是简单的 `key: value` 文本：

```text
version: 1.0.0
cpu_num: 128
freq: 49
record_interval: 1
persistent_day: 7
record_env_name: POD_NAME
kernel_stack: 0
stack_size: 8192
```

当前实现稳定写入这些键：

- `version`
- `cpu_num`
- `freq`
- `record_interval`
- `persistent_day`
- `record_env_name`
- `kernel_stack`
- `stack_size`

读取侧会忽略 `conf` 中的未知键，仅处理当前字段定义。

## `strmap`

`strmap` 是字符串表，按行组织，行格式为：

```text
<string> <id>\n
```

示例：

```text
java;main;foo 123
bar_[k] 124
abc            xyz            -67890-3-1234|pod-a 125
```

用途：

- 普通栈帧字符串都会先去重后落到 `strmap`。
- metadata 头也以“字符串”的方式进入 `strmap`，并作为一条栈的第一个 string id。
- 内核符号通常以 `_[k]` 后缀区分。

`strmap` 是追加写入的。目录轮转期间，后续 interval 只会把新出现的字符串继续 append 到同一个压缩文件中。

## `idsmap`

`idsmap` 是“一个折叠栈由哪些 string id 组成”的映射表，按行组织，格式为：

```text
<sid1>;<sid2>;...; <ids_id>\n
```

示例：

```text
125;124;123; 10
```

说明：

- `ids_id` 是一条聚合栈的逻辑编号。
- 左侧是该栈对应的 string id 列表。
- 第一个 `sid` 约定是 metadata 对应的 string id。
- 后续 `sid` 才是实际的栈帧序列。

和 `strmap` 一样，`idsmap` 也是持续 append 的。

## `stack.bin`

`stack.bin` 是核心时间序列文件，仍然使用 zstd 压缩，但其解压结果是二进制格式。

### 顶层布局

每个 record 的布局如下，整数均为 little-endian：

```text
u8[2]   header      = 0xFA 0xFB
u64     start_ms
u64     end_ms
u64     entry_len
repeat entry_len times:
    u32 ids_id
    u64 count
u8[2]   footer      = 0xFC 0xFD
```

### 字段语义

- `start_ms` / `end_ms`
  - 相对当天 00:00:00 的毫秒偏移。
  - 如果 store 跨天，读取侧会在 `end_ms < first_start_ms` 时补加一天的毫秒数。
- `entry_len`
  - 当前 record 内的聚合项数量。
- `ids_id`
  - 指向 `idsmap` 的逻辑栈编号。
- `count`
  - 该 record 时间桶内该栈的累计样本数。

### 一个最小示例

```text
[0xFA,0xFB]
start_ms=1000
end_ms=2000
entry_len=2
  (ids_id=10, count=100)
  (ids_id=11, count=200)
[0xFC,0xFD]
```

### 读取侧注意事项

- C 侧 `cpa show` 以 header/footer 扫描 record。
- Rust `cpa_show` 在索引解压后的 `stack.bin` 时，当前实现会额外丢弃最后一个 record，作为“末尾可能仍在 flush”这一场景的保守防御。
- 因为 `stack.bin` 是增量追加写，线上读者应当容忍目录末尾存在“刚写到一半”的窗口。

## metadata 编码

每条聚合栈的第一个 `sid` 对应 metadata 字符串，当前编码格式固定为：

```text
<comm(15字节，空格补齐)+group_comm(15字节，空格补齐)>-<cgroup_id>-<cpu>-<pid>|<env>
```

示例：

```text
nginx          nginx          -123456-7-4321|pod-a
```

字段解释：

- `comm`
  - 线程名，固定宽度 15 字节，尾部用空格补齐。
- `group_comm`
  - 进程组 / group leader 的 comm，固定宽度 15 字节。
- `cgroup_id`
  - 来自采样时内核 task 的 cgroup id。
- `cpu`
  - 采样 CPU。
- `pid`
  - 进程 pid。
- `env`
  - 从 `record_env_name` 指定的环境变量中取出的值；取不到时默认写入 `SYSTEM`。

## 隐含依赖与准确性说明

### `env` / `pod`

Rust TUI 和过滤语义里常把 `env` 字段显示成 `pod`，但该字段仍来自采集到的环境变量，不表示 CPA 直接接入 Kubernetes API。

当前实现的真实行为是：

- `cpa monitor --record_env_name` 指定一组环境变量名。
- 运行时按给定顺序扫描 `/proc/<pid>/environ`，找到第一个匹配键就把值写进 metadata。
- 如果没有任何匹配值，则写入 `SYSTEM`。

因此：

- 如果业务进程没有把 `POD_NAME`、`MY_SERVICE` 之类的值注入到环境变量里，`pod` 维度就不会准确。
- 如果多个候选环境变量都存在，只会保留第一个匹配值。
- 该值会按 pid context 做缓存，因此如果进程运行中主动修改环境变量，metadata 里的标签可能滞后。

### `cgroup_id`

`cgroup_id` 由采样时内核 task 直接提供，语义上比 `env/pod` 更“硬”：

- 它不依赖用户态约定。
- 不依赖业务是否正确注入环境变量。
- 在 BPF 路径下可以认为是采样点上的直接内核观测值。

需要注意的是，当前 perf 后端并不会像 BPF 后端那样从内核事件里补全 cgroup id，因此 perf store 中这一列可能为 `0`。

## 设计取舍

### 为什么保留 `pid`，不保留 `tid`

当前 store 把 `pid` 落入 metadata，但不把 `tid` 作为主键长期保存。原因是持续 profiling 的核心目标是做低基数、可长期聚合的目录存储：

- `tid` 基数高、生命周期短，直接入盘会明显放大 `strmap/idsmap` 规模。
- 线程池、协程 runtime、短命线程会让 `tid` 维度快速失真，降低长期对比价值。
- 多数线上分析更关心“进程 / 服务级路径”，而不是每个瞬时线程 id。

当前的折中是：

- metadata 仍保留 `comm` 和 `group_comm`。
- 展示层可用 `--show_thread_name` 补线程名。
- 真正的长期聚合标签仍以 `pid/group_comm/cgroup_id/env` 这类较稳定维度为主。

### 为什么用目录格式而不是在线协议

CPA 当前选择“落盘目录 + 读目录展示”的方式，而不是采集端直接暴露在线 RPC：

- `cpa show` 和内嵌 TUI 可以复用同一套 store。
- 故障排查时更容易打包、归档、复现。
- 二进制 `stack.bin` 和文本 sidecar 组合更利于持续追加写。

这也是为什么 `decompressed/` 被设计成 viewer 侧缓存，而不是正式采集产物的一部分。
