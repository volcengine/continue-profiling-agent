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
- `--pid <pid>`：限制到某个进程
- `--comm <name>`：按进程名过滤
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
