# CPA 使用手册

[返回 README](../../README.zh-CN.md)

完整的公开选项说明请参考 [README.zh-CN.md](../../README.zh-CN.md) 中的
`选项总览` 一节。

## 前置条件

- 已构建出 `build/bin/cpa`
- 运行环境具备所需的 BPF/perf 能力
- 大多数 `cpa monitor` 场景需要 root 权限

## `cpa monitor`

`cpa monitor` 负责采样并写出 profile 数据目录。

基础持续剖析：

```bash
sudo mkdir -p /var/log/cpa
sudo ./build/bin/cpa monitor \
  --store_dir /var/log/cpa \
  --freq 49
```

常用参数：

- `--backend bpf|perf`：选择采样后端
- `--pid`、`--comm` 等进程选择选项：见下面「选择采集哪些进程」
- `--record_interval <sec>`：控制存储和查询粒度
- `--persistent_day <days>`：仅保留最近若干天的目录
- `--record_env_name <k1,k2>`：记录指定环境变量键，供 `cpa show` 后续过滤
- `--parse_env_values <v1,v2>`：只对匹配环境值的进程做用户态栈解析
- `--bench`：在运行状态里按 stat 周期打印最终 DWARF 路径 benchmark，包括实际回溯次数、速率、平均/最小/最大耗时和固定耗时桶。`FP_BETTER` 样本不计入。首次符号/CFI 冷加载可能体现在前几个周期。

一次性采样：

```bash
sudo ./build/bin/cpa monitor \
  --pid 12345 \
  --oneshot \
  --output_prof /tmp/cpa.prof
```

off-CPU 采集：

```bash
sudo ./build/bin/cpa monitor \
  --pid 12345 \
  --offcpu 1
```

probe 触发采集：

```bash
sudo ./build/bin/cpa monitor \
  --pid 12345 \
  --probe kprobe:try_to_free_pages
```

切到 perf 后端（仅支持 on-CPU 持续采样）：

```bash
sudo ./build/bin/cpa monitor \
  --backend perf \
  --store_dir /var/log/cpa
```


## 选择采集哪些进程

默认采集所有进程。下面的选项用来缩小范围（仅 BPF 后端）。不同选项之间是"且"，
同一选项里逗号分隔的值之间是"或"；互相矛盾的组合在解析命令行时就会被拒绝。

- `--pid <p1,p2,...>`：这些进程（最多 16 个）
- `--comm <n1,n2,...>`：进程名是其中之一的进程（最多 8 个）。进程名在进程启动或
  exec 时判断，所以 exec 成这个名字的 shell 会被选中，exec 成别的程序的进程会被
  移出。名字精确匹配，最多 15 字节（内核只保留这么长）。
- `--thread_comm <name>`：线程名是它的线程，单独用或配一个 `--pid`（即原来
  `--comm` 的语义）
- `--exe <path1,...>`：运行这些可执行文件之一的进程，按设备号和 inode 比较
  （最多 4 个）
- `--cgroup <path1,...>`：在这些 cgroup 之一中的进程，路径相对 cgroup v1 的
  `cpu` 挂载点或 cgroup v2 挂载点（最多 8 个）；加 `--cgroup_recursive` 包含下层
  cgroup（最多 8 层）。需要内核的 cgroupfs 向用户态提供 cgroup id（upstream 4.15 及以上，部分发行版内核更早就有）；否则直接报错。
- `--container_pid <pid>`：这个进程所在 cgroup 及其下层的所有进程
- `--children`：同时采集被选进程启动的子进程，以及子进程的子进程，包括 monitor
  启动时已经在运行的
- `--new_only`：只选 monitor 就绪之后才启动的进程。就绪时日志打印
  `target: waiting for a matching process`（启动约需一秒，老内核更久）；在这行
  之前启动的进程不会被选中
- `--first_match`：只选第一个启动并匹配的进程；它退出或采集时间窗结束后，本次
  运行自动结束
- `--startup_window <sec>`：每个被选中的进程只采集被选中后的这么多秒

示例：

```bash
# 所有 java 进程，包括之后启动的
sudo ./build/bin/cpa monitor --comm java

# 下一个由这个程序启动的进程，只采前 60 秒
sudo ./build/bin/cpa monitor --exe /opt/app/bin/server --first_match --startup_window 60

# 某个容器的所有进程
sudo ./build/bin/cpa monitor --container_pid 4242
```

选择结果存在一个 BPF map 里：规则只在进程诞生（exec、fork）时判断一次，采样时
只查一次这个 map，所以选择本身对每个样本只多一次查找。

## 崩溃与非零退出时的调用栈

`--enable_coredump_capture` 在进程 core dump 时记录它的调用栈。
`--enable_exit_capture` 为每个被选中、经 `exit_group(2)` 或致命信号以非零状态结束的进程记录一条调用栈，在内存释放之前：

```text
<# EXIT NONZERO raw=768 exit=3 #>          exit(3)；raw 是 wait(2) 状态字
<# EXIT NONZERO raw=15 sig=15 core=0 #>    被 SIGTERM 杀死
```

两者都只用于 BPF on-CPU 采样：与 `--offcpu`、`--oneshot`、`--probe` 或 `--kernel_stack`（exit 采集）同时使用时启动即报错。帧带符号+偏移、pc、build-id 和完整路径，便于离线解析。

全机每个进程退出都会经过 exit 的 hook，所以 exit 采集必须有目标：它自己的

- `--exit_comm <n1,n2>`：这些进程名（最多 8 个），或
- `--exit_pid <p1,p2>`：这些正在运行的进程（最多 16 个），二者不能同时用；

它们只决定记录哪些退出，不影响采样范围。不给时沿用进程选择（`--pid`、`--comm` 等）；不支持全机范围的 exit 采集。

`--exit_target_env_name MY_POD_NAME,POD_NAME` 配合 `--exit_target_env_values <v,...>`（完全相等）和/或 `--exit_target_env_value_prefix <p,...>`（前缀），只保留按列出顺序第一个设了非空值的变量满足条件的进程的退出，必须配 `--exit_comm` 或 `--exit_pid`。环境变量在进程被选中时读取（exec 或 fork 成 `--exit_comm` 的名字时、启动扫描时、`--exit_pid` 在启动时），因为退出时已经读不到；还没读到就退出的进程直接丢弃。统计日志里有 `Exit Capture Count`、`Exit Env Mismatch Drop` 和 `Exit Env Unknown Drop`。

有意不做的事：

- leader 用裸 `exit(2)` 系统调用退出、且没有组退出时不记录（需要挂在每个线程退出路径上）；
- 进程的映射视图里没有它退出时所在的库时，退出记录的用户态帧可能缺失：它从未被采样过，或在 exec 时被选中、视图是在动态链接器还在运行时读的（`--unwind_workers` 大于 1 时更常见，第一个样本被回溯得更早）。一个进程的映射 30–90 秒内最多重读一次，而退出记录被回溯时进程已经不在，读不到了；
- 多个线程同时用不同的码调用 `exit_group` 时，记录的是先进入者的码。

查看：

```bash
./build/bin/cpa show --read /var/log/cpa/cpa_YYMMDD --list_exit \
  --starttime 00:00:00 --endtime 23:59:59 --core_verbose
```

`--list_core` 列出 coredump 样本，`--list_exit` 列出 exit 样本（不能同用），每条一块：元数据、退出码和帧；`--target_*` 过滤同样适用。`--core_verbose` 用 addr2line 把原生帧解析到源码行（`CPA_ADDR2LINE` 可指定工具），先查二进制本身，再按 build-id 查 `/usr/lib/debug` 或 `--core_debug_dir` 下的调试文件；`--core_container_pid <pid>` 通过 `/proc/<pid>/root` 解析容器路径。TUI 里按 `L` 打开同一个列表。

## `cpa show`

`cpa show` 用于读取 `cpa monitor` 生成的 profile 目录。

查看可用时间范围：

```bash
./build/bin/cpa show \
  --read /var/log/cpa/cpa_YYMMDD \
  --show_range 1
```

导出 flamegraph：

```bash
./build/bin/cpa show \
  --read /var/log/cpa/cpa_YYMMDD \
  --output_prof cpa.prof
```

未显式指定时间范围时，导出会从第一个匹配当前筛选条件的 record 开始。

按落盘 record 时间线里的绝对时间范围导出：

```bash
./build/bin/cpa show \
  --read /var/log/cpa/cpa_YYMMDD \
  --starttime 00:10:00 \
  --endtime 00:15:00 \
  --output_prof cpa.prof
```

常用过滤参数：

- `--target_pid <pid>`
- `--target_comm <name>`
- `--target_env <value>`
- `--target_cgroup_id <id>`
- `--target_cpu <set>`

其他常用参数：

- `--show_thread_name 1`：在 flamegraph 中展示线程名
- `--no_pid 1`：不在栈帧中显示 pid 后缀
- `--no_env 1`：不在栈帧中显示 env 标签
- `--show_raw 1`：输出原始 metadata
- `--output_num <n>`：从选中时间点向后导出 `n` 个 record，建议使用正整数
- `--split_path <dir>`：将选中时间范围拆分导出为原始文件

打开内嵌 Rust TUI：

```bash
./build/bin/cpa show \
  --read /var/log/cpa/cpa_YYMMDD \
  --use_cui
```

TUI 支持时间窗口浏览、火焰图缩放和交互式过滤。详细说明见
[src/cpa_show/doc/cpa_show.md](../../src/cpa_show/doc/cpa_show.md)。

## `cpa capabilities`

打印当前内核允许 `cpa monitor` 做什么，每行一个 `key: value`。每项能力都是实际
加载一个小 BPF 程序或 map 探测出来的，不靠内核版本号推断，所以回合的补丁也算数：

```bash
sudo ./build/bin/cpa capabilities
```

```text
schema_version: 1
kernel.release: 5.15.152-amd64
capability.get_stack_perf_event.state: supported
capability.get_stack_perf_event.reason: probe_succeeded
capability.get_stack_perf_event.error_code: 0
...
```

state 取值：`supported`、`unsupported`（内核没有）、`unavailable`（没有权限，
请用 root 运行）、`probe_error`（errno 见 `error_code`）。各项能力：

- `get_stack_perf_event`、`get_stack_kprobe`、`get_stack_tracepoint`：三种程序
  类型下的 `bpf_get_stack`；三者不全时使用 lite 采集对象（见内核兼容性说明）；
- `perf_event_program_load`、`kprobe_program_load`、`tracepoint_program_load`：
  定时采样、`--offcpu` / `--probe kprobe:...`、`--probe tracepoint:...` 加载的程序类型；
- `process_exit`：每次运行都会挂的进程退出 tracepoint 程序；
- `coredump`：`--enable_coredump_capture` 用的 `do_coredump` kprobe；
- `ringbuf`：ring buffer 数据通路（`--datapath auto` 在有时使用）。

`cpa monitor` 选择 BPF 对象时读的就是这份缓存结果。只有某个 key 的含义改变时
`schema_version` 才会变。

## 输出与存储说明

- 默认持续存储目录根是 `/var/log/cpa`
- 默认 one-shot 输出文件名是 `cpa.prof`
- `cpa show` 读取的是 `cpa monitor` 生成的目录，而不是任意 flamegraph 文本
- `--use_cache 1` 允许 `cpa show` 复用解压后的中间文件

## 典型使用流程

1. 对目标 workload 启动 `cpa monitor`
2. 等待写出一个或多个 profile 目录
3. 用 `cpa show --show_range 1` 看可用时间区间
4. 导出 flamegraph，或用 TUI 做交互分析
