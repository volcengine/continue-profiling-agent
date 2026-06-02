# continue-profiling-agent

[English](README.md)

`continue-profiling-agent`（`cpa`）是一个面向 Linux 的持续剖析工具，
目标是在性能问题已经发生之后，仍然能回看当时的执行现场。它以极低开销在
生产机器上持续记录 profiling 历史，让工程师可以事后定位具体时间窗口，
而不是依赖复现或等待下一次异常。

![CPA TUI](docs/assets/technical-deep-dive/02-cpa-tui.png)

## 为什么需要 CPA

- 极低开销、近乎无感：通过极致优化的 libgunwinder，CPA 可以在极低开销下，
  甚至无感的情况下，持续记录整机所有进程的秒级火焰图。
- 持续留存现场：CPA 在本机滚动保留最近的秒级 profiling 历史。
- 对用户进程零侵入：CPA 不修改、不注入、不重启用户进程，可以常驻运行而不
  改变应用行为。
- 面向故障排查：`cpa show` 可以导出 flamegraph，也可以打开交互式 TUI，
  直接跳到故障发生的绝对时间。

## 命令

CPA 提供两条主要命令：

- `cpa monitor`：采集并持久化 profile 数据
- `cpa show`：读取存储数据，导出 flamegraph 或进入内嵌 Rust TUI

## 当前能力范围

- 基于 BPF 或 perf 的持续 on-CPU profiling
- off-CPU 采集
- 基于 probe 的内核栈触发采集
- `store_dir` 下的持久化与目录轮转
- `cpa show` 导出 flamegraph
- `cpa show --use_cui` 打开的内嵌 Rust TUI

## 架构概览

CPA 可以分成四层：

1. CLI 层
   - `cpa monitor` 负责解析采集和过滤参数。
   - `cpa show` 负责读取 profile 目录，并输出 flamegraph 或进入 TUI。
2. Profiling runtime
   - 运行时由一组 worker 组成，分别处理采集、unwind、存储轮转、本地状态统计和调试。
3. BPF / perf 采集后端
   - BPF 路径使用 CO-RE 程序与 `bpf/` 下的 host loader。
   - perf 路径保留为另一条采样后端。
4. 存储与展示
   - `cpa monitor` 写出包含 `conf`、`strmap`、`idsmap`、`stack.bin` 等文件的 profile 目录。
   - `cpa show` 和 Rust `cpa_show` 直接消费这些目录。

详细说明见 [docs/zh-CN/architecture.md](docs/zh-CN/architecture.md)。

其中：

- 存储文件格式详见 [docs/zh-CN/store-format.md](docs/zh-CN/store-format.md)
- 后端能力、启动检查与回退语义详见 [docs/zh-CN/backend-modes.md](docs/zh-CN/backend-modes.md)
- BPF 第三方依赖来源与 pin 方式详见 [docs/zh-CN/bpf-dependencies.md](docs/zh-CN/bpf-dependencies.md)
- 技术解读详见 [docs/zh-CN/technical-deep-dive.md](docs/zh-CN/technical-deep-dive.md)

## 构建

前置条件：

- 支持 eBPF CO-RE 的 Linux 环境
- `cmake >= 3.10`
- `clang`、`llvm-strip`、`llvm-objdump`
- `python3`
- `cargo`
- `make`
- `elf`、`dw`、`zstd`、`crypto`、`iberty` 对应的开发库
- 已从 GitHub 初始化的 `libs/libgunwinder` submodule

构建命令：

```bash
git submodule update --init --recursive
cmake -S . -B build
cmake --build build -j
```

主可执行文件位于 `build/bin/cpa`。

如果需要生成由
[SOPacker](https://github.com/XinShuichen/sopacker)
打包的单文件 portable 分发产物，可以额外执行：

```bash
cmake --build build -j --target cpa_portable
```

该目标会生成 `build/bin/cpa_portable`。它打包的是动态链接的 `cpa`
可执行文件及其依赖的 shared libraries，不会把 LGPL 组件静态链接进
Apache 主程序。如需复用本地 checkout，可通过
`-DCPA_BPF_SOPACKER_DIR=/path/to/sopacker` 指向已有的 SOPacker 目录。

portable 产物本质是一个自解包脚本，主要解决分发问题：目标机器可以不预装
`libgunwinder`，但 CPA 仍然保持动态链接。因此需要验证另一个 LGPL 构建，
或部署修复后的 unwinder 时，仍然可以替换 `libgunwinder.so`。

替换 `cpa_portable` 中 bundled `libgunwinder.so` 的步骤如下：

```bash
# 先解包，并顺便执行一个轻量命令。
./cpa_portable version

# 生成脚本的开头会记录解包目录。
tmpdir=$(sed -n 's/^tempdir=//p' ./cpa_portable | head -n1)

# 替换解包后的 shared object。替换版本需要 ABI 兼容，并建议保留
# libgunwinder.so 这个 SONAME。
cp /path/to/libgunwinder.so "$tmpdir/libgunwinder.so"

# 再次运行 portable 产物。只要解包后的 cpa 仍匹配内置 checksum，
# SOPacker 会复用当前解包目录。
./cpa_portable version
```

如果只是临时验证，也可以显式 preload，不修改临时目录：

```bash
LD_PRELOAD=/path/to/libgunwinder.so ./cpa_portable version
```

如果 `/tmp` 被清理，或 portable 产物本身更新，需要重新执行解包和替换步骤。

完整构建与测试说明见 [docs/zh-CN/build.md](docs/zh-CN/build.md)。

## libgunwinder CFI Benchmark

`libgunwinder` 提供 `cfi_bench`，用于单独测量 DWARF CFI frame evaluator
的开销。以下数据在 2026-06-01 实测，机器为 Intel(R) Xeon(R) Platinum
8336C CPU @ 2.30GHz，Linux 5.15.152，GCC 8.3.0。每行取固定 CPU0
后三次运行的中位数：

```bash
taskset -c 0 libs/libgunwinder/bin/cfi_bench \
  --frames 20000000 --set-size <N> --warmup 10000
```

| Working set | CFI frames/s | 平均 ns/frame | P50 ns | P99 ns | 16 帧采样/s | 32 帧采样/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | 11,998,307 | 83.35 | 70.11 | 167.27 | 749,894 | 374,947 |
| 1,000 | 4,227,484 | 236.55 | 228.41 | 327.33 | 264,218 | 132,109 |
| 10,000 | 1,353,664 | 738.74 | 737.73 | 862.48 | 84,604 | 42,302 |

采样速率列是理论值，计算方式为 CFI frames/s 除以平均栈深度。CPA
端到端吞吐还包含采样、排队、符号格式化、store 写入以及 ELF/CFI 冷加载。

## 快速开始

从最新 release 安装 CPA，并启动 systemd 服务：

```bash
curl -fsSL https://raw.githubusercontent.com/volcengine/continue-profiling-agent/main/tools/install_cpa.sh | sudo bash
```

检查服务状态：

```bash
sudo systemctl status cpa.service
cpa version
```

CPA 默认把 profiling 数据写到 `/var/log/cpa`。查看某个 profile 目录的可用
时间范围：

```bash
cpa show --read /var/log/cpa/cpa_YYMMDD --show_range 1
```

导出 flamegraph：

```bash
cpa show --read /var/log/cpa/cpa_YYMMDD --output_prof cpa.prof
```

打开内嵌 Rust TUI：

```bash
cpa show --read /var/log/cpa/cpa_YYMMDD --use_cui
```

卸载 CPA，但保留 profiling 数据：

```bash
curl -fsSL https://raw.githubusercontent.com/volcengine/continue-profiling-agent/main/tools/install_cpa.sh | sudo bash -s -- --uninstall
```

更多示例见 [docs/zh-CN/usage.md](docs/zh-CN/usage.md)。

## 部署

GitHub Release 发布后，可以直接安装 Linux x86_64 portable 包：

```bash
curl -fsSL https://raw.githubusercontent.com/volcengine/continue-profiling-agent/main/tools/install_cpa.sh | sudo bash
```

安装指定 release tag：

```bash
curl -fsSL https://raw.githubusercontent.com/volcengine/continue-profiling-agent/main/tools/install_cpa.sh | sudo bash -s -- --version v1.0.0
```

如果使用本地构建产物，建议使用 systemd 托管 CPA，可以直接使用部署脚本：

```bash
sudo tools/deploy_cpa.sh --binary build/bin/cpa
```

如果目标机器没有 `/sys/kernel/btf/vmlinux`，需要先用 `pahole` 基于匹配当前
内核的 debug-info `vmlinux` 生成 detached BTF，并显式传入：

```bash
sudo mkdir -p /etc/cpa
sudo pahole --btf_encode_detached=/etc/cpa/vmlinux.btf \
  /usr/lib/debug/boot/vmlinux-$(uname -r)
sudo tools/deploy_cpa.sh --binary build/bin/cpa --btf /etc/cpa/vmlinux.btf
```

脚本会创建 `/var/log/cpa`，写入 `/etc/cpa/cpa.conf`，安装
`cpa.service` systemd unit，并默认以 49 Hz 启动 CPA。完整说明见
[docs/zh-CN/deploy.md](docs/zh-CN/deploy.md)。

## 选项总览

共享通用选项：

- `--help, -h`：打印帮助。
- `--verbose, -v`：开启更详细的 CLI 日志。
- `--config, -C <FILE>`：从配置文件覆盖选项，格式为 `{arg_name}: {arg_val}`。
- `--btf_path, -b <PATH>`：指定 BPF 后端使用的自定义 BTF 文件路径；如果它不可读或不是合法 BTF，启动检查会失败。
- `--duration, -d <SEC>`：让 `cpa monitor` 在指定秒数后退出。

`cpa monitor` 选项：

- `--store_dir, -s <DIR>`：持续采集目录根路径。
- `--backend <bpf|perf>`：选择采样后端。`perf` 只支持 on-CPU 持续采样；如果请求是普通 on-CPU 持续模式，BPF 不满足时 CPA 可以自动回退到 `perf`。
- `--freq, -F <HZ>`：采样频率。
- `--record_interval, -r <SEC>`：存储轮转和查询粒度。
- `--persistent_day, -P <DAYS>`：只保留最近 N 天的持续采集目录。
- `--oneshot`：不做目录轮转，只输出一个 flamegraph profile。需要 BPF 后端。
- `--output_prof, -o <PATH>`：one-shot 模式输出路径，默认 `cpa.prof`。
- `--pid, -p <PID>`：只采集指定 pid。需要 BPF 后端。
- `--comm, -n <NAME>`：按 comm/group-comm 过滤采集对象。需要 BPF 后端。
- `--kernel_stack, -K`：只采集内核态栈。需要 BPF 后端。
- `--offcpu, -u`：采集 off-CPU 样本，只能与 BPF 后端一起使用。
- `--probe <SPEC>`：仅在指定 probe 触发时采集栈，采用 bpftrace 风格语法，例如 `kprobe:try_to_free_pages`。
- `--disable_sym, -S`：关闭符号解析，尽量保留原始地址。
- `--include_full_path`：在可用时保留完整文件路径。
- `--strip_name_disable`：关闭 Go 符号名裁剪。
- `--record_env_name, -R <LIST>`：把这些环境变量键写入 metadata，供 `cpa show` 后续过滤。
- `--parse_env_values, -V <LIST>`：只对环境变量值匹配该列表的进程做用户态展开。
- `--max_queue_size, -m <N>`：内存中 stack event 队列的上限。
- `--stack_size <BYTES>`：BPF 后端用户态栈抓取缓冲大小，必须 4K 对齐，范围 `[4096, 65536]`。perf 后端不支持自定义这一语义。
- `--max_cache_size_mb <MB>`：符号和调试缓存超过该限制时重启 monitor。
- `--max_store_size_mb <MB>`：store 目录超过该限制时重启 monitor，并清理旧目录。
- `--log_print_cycles <N>`：每 N 个 timer 周期打印一次本地运行状态。
- `--bench`：在运行状态里打印 DWARF 回溯 benchmark，包括速率、平均/最小/最大耗时和固定耗时分桶。
- `--debug_option <PID,FREQ,PATH>`：调试抓取参数，格式 `{pid},{sample_freq},{dump_path}`。

`cpa show` 选项：

- `--read, -r <DIR>`：输入 CPA profile 目录。
- `--starttime, -B <HH:MM:SS>`：落盘 record 时间线里的起始绝对时间。
- `--endtime, -E <HH:MM:SS>`：落盘 record 时间线里的结束绝对时间。
- `--output_num, -n <N>`：从选中时间点开始导出连续 N 个 record，必须为正整数。
- `--output_prof, -o <PATH>`：flamegraph 输出路径。不显式指定时间时，
  导出会从第一个匹配 record 开始；未指定输出路径时自动生成
  `cpa_<time>_<n>.prof`。
- `--show_range, -p`：打印可用 record 时间范围后退出。
- `--use_cui, -G`：打开内嵌 Rust `cpa_show` 终端界面。
- `--use_cache, -u`：复用 `decompressed/` 下的中间文件，不重复解压。
- `--split_path <DIR>`：把选中时间范围拆分导出为原始文件到该目录。
- `--show_thread_name, -S`：在 flamegraph 中显示线程名。
- `--no_pid, -P`：不在 metadata 标签中显示 pid 后缀。
- `--no_env, -V`：不在 metadata 标签中显示 env 标签。
- `--show_raw, -R`：直接输出原始 metadata，而不是格式化后的 CPA 标签。
- `--target_pid <PID>`：过滤到指定 pid。
- `--target_comm <NAME>`：过滤到指定 process group comm。
- `--target_env <VALUE>`：过滤到指定环境变量值。
- `--target_cgroup_id <ID>`：过滤到指定 cgroup ID。
- `--target_cpu <CPUSET>`：过滤到指定 CPU 集合，例如 `1-3,5,7-9`。

## 文档导航

English:

- [Architecture](docs/en/architecture.md)
- [Technical Deep Dive](docs/en/technical-deep-dive.md)
- [Store Format](docs/en/store-format.md)
- [Backends and Capability Checks](docs/en/backend-modes.md)
- [BPF Third-Party Dependencies](docs/en/bpf-dependencies.md)
- [Usage Guide](docs/en/usage.md)
- [Deployment Guide](docs/en/deploy.md)
- [Build Guide](docs/en/build.md)
- [Test Coverage Guide](docs/en/testing.md)
- [Development Guide](docs/en/development.md)
- [Contributing](CONTRIBUTING.md)

中文：

- [架构说明](docs/zh-CN/architecture.md)
- [技术解读](docs/zh-CN/technical-deep-dive.md)
- [存储格式说明](docs/zh-CN/store-format.md)
- [后端与能力检查](docs/zh-CN/backend-modes.md)
- [BPF 第三方依赖](docs/zh-CN/bpf-dependencies.md)
- [使用手册](docs/zh-CN/usage.md)
- [部署指南](docs/zh-CN/deploy.md)
- [构建指南](docs/zh-CN/build.md)
- [测试覆盖说明](docs/zh-CN/testing.md)
- [开发指南](docs/zh-CN/development.md)
- [贡献指南](CONTRIBUTING.zh-CN.md)

组件文档：

- [CPA Monitor 运行时说明](src/cpa_monitor/README.md)
- [cpa_show 概览](src/cpa_show/README.md)
- [cpa_show user guide (English)](src/cpa_show/doc/cpa_show.en.md)
- [cpa_show 用户手册](src/cpa_show/doc/cpa_show.md)

## 测试

仓库包含 Python 集成测试，主要位于 `tests/`。

```bash
pytest -q tests/cpa
```

测试覆盖范围说明见 [docs/zh-CN/testing.md](docs/zh-CN/testing.md)。

其中很多测试依赖：

- 已构建好的 `build/bin/cpa`
- root 权限
- 能加载测试模块的内核与工具链环境

## 仓库布局

- `src/`：用户态 CLI、`cpa monitor`、`cpa show` 以及 `cpa_show` Rust 集成
- `bpf/`：BPF 程序、host 侧 loader、skeleton 生成、`libbpf` / `bpftool` submodule 与构建辅助
- `tests/`：单元和集成测试
- `docs/`：中英文项目文档与设计记录

## 项目说明

- `cpa_show` 只以内嵌 Rust 库形式构建，用于 `cpa show --use_cui`，不作为独立可执行程序发布。
- `libgunwinder` 通过 `libs/libgunwinder` submodule 跟踪。CMake 构建会调用
  它的 Makefile，把 `libgunwinder.so` 复制到 `build/bin/cpa` 旁边，并通过
  `$ORIGIN` 运行时搜索路径动态链接。
- 默认存储目录是 `/var/log/cpa`。
- 默认 one-shot 输出文件名是 `cpa.prof`。

## 社区与治理

- [贡献指南](CONTRIBUTING.zh-CN.md)
- [安全策略](SECURITY.md)
- [行为准则](CODE_OF_CONDUCT.md)
- [致谢](ACKNOWLEDGEMENTS.md)

## 许可证

本仓库采用 Apache License 2.0。详见 [LICENSE](LICENSE)。
