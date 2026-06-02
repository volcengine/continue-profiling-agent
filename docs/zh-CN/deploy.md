# CPA 部署指南

[返回 README](../../README.zh-CN.md)

本文说明最小 systemd 部署方式。默认部署以 49 Hz 做持续 on-CPU
profiling，并把数据写到 `/var/log/cpa`。


## 发行版环境准备

如果直接使用 Release 安装脚本，目标机器只需要常规 Linux userspace、
`systemd`、`curl`，以及写入 `/usr/local`、`/etc/cpa`、
`/etc/systemd/system` 和 `/var/log/cpa` 的权限。portable release 产物已经
携带 CPA 及其打包的 shared-library runtime。

如果需要在部署前本地构建 CPA，可参考下面的依赖安装命令。

Ubuntu：

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  autoconf automake binutils-dev build-essential clang cmake curl git \
  libdw-dev libelf-dev libiberty-dev libssl-dev libtool libzstd-dev \
  llvm make pkg-config python3 zlib1g-dev zstd cargo
```

Debian：

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  autoconf automake binutils-dev build-essential clang cmake curl git \
  libdw-dev libelf-dev libiberty-dev libssl-dev libtool libzstd-dev \
  llvm make pkg-config python3 zlib1g-dev zstd cargo
```

CentOS Stream 或 Fedora：

```bash
sudo dnf install -y \
  autoconf automake binutils-devel clang cmake curl elfutils-devel \
  elfutils-libelf-devel gcc gcc-c++ git libiberty-devel libtool llvm \
  make openssl-devel pkgconf-pkg-config python3 rust cargo zlib-devel \
  zstd zstd-devel
```

CPA 需要 `cmake >= 3.10`。配置前先确认 CMake 版本：

```bash
cmake --version
```

如果较老的 CentOS 系统里 `/usr/bin/cmake` 版本过低，可安装 `cmake3`，并
用 `cmake3` 执行配置和构建：

```bash
sudo yum install -y epel-release
sudo yum install -y cmake3
cmake3 -S . -B build
cmake3 --build build -j
```

如果默认 LLVM 版本过旧，可以从 apt.llvm.org 安装 LLVM 15，并把它放到
shell `PATH` 前面：

```bash
wget https://apt.llvm.org/llvm.sh
chmod +x ./llvm.sh
sudo ./llvm.sh 15

# 把这一行加入你的 shell 启动文件，例如 ~/.bashrc 或 ~/.zshrc。
export PATH=/usr/lib/llvm-15/bin:$PATH
```

然后配置时传入 `-DCPA_BPF_LLVM_VERSION=15`。

部署前还需要阅读
[docs/zh-CN/kernel-compatibility.md](kernel-compatibility.md) 中的内核风险说明。

## 构建 Agent

可以在目标机器构建，也可以在兼容的构建机上构建：

```bash
git submodule update --init --recursive
cmake -S . -B build
cmake --build build -j
```

部署脚本默认使用 `build/bin/cpa`。普通动态链接构建还需要同目录下的
`build/bin/libgunwinder.so`。

## BTF 准备

BPF 后端会优先使用目标机器提供的 `/sys/kernel/btf/vmlinux`：

```bash
test -r /sys/kernel/btf/vmlinux && echo "system BTF is available"
```

如果目标机器没有 system BTF，需要用和当前运行内核完全匹配的 debug-info
`vmlinux` 通过 `pahole` 生成 detached BTF，然后显式传入：

```bash
sudo mkdir -p /etc/cpa
sudo pahole --btf_encode_detached=/etc/cpa/vmlinux.btf \
  /usr/lib/debug/boot/vmlinux-$(uname -r)
```

不同发行版的 debug-info `vmlinux` 路径可能不同。关键要求是输入文件必须和
运行中的内核一致。直接运行 CPA 时，用
`cpa monitor --btf_path /etc/cpa/vmlinux.btf` 指定 detached BTF。使用部署
脚本时，用 `tools/deploy_cpa.sh --btf /etc/cpa/vmlinux.btf` 指定同一个文件；
脚本会把该路径写入 `/etc/cpa/cpa.conf` 的 `btf_path` 字段。

## Release 安装脚本

GitHub Release 发布后，可以直接安装 Linux x86_64 portable 包：

```bash
curl -fsSL https://raw.githubusercontent.com/volcengine/continue-profiling-agent/refs/heads/main/tools/install_cpa.sh | sudo bash
```

安装指定版本：

```bash
curl -fsSL https://raw.githubusercontent.com/volcengine/continue-profiling-agent/refs/heads/main/tools/install_cpa.sh | sudo bash -s -- --version v1.0.0
```

安装脚本会从 GitHub Releases 下载 `cpa_portable-linux-x86_64`，然后调用
`tools/deploy_cpa.sh`。部署参数可以追加在 `--` 后面，例如 `--no-start`、
`--freq`、`--store-dir` 或 `--btf`。

## 一键部署

使用本地构建产物时，以 root 执行：

```bash
sudo tools/deploy_cpa.sh \
  --binary build/bin/cpa \
  --btf /etc/cpa/vmlinux.btf
```

如果系统已经提供 `/sys/kernel/btf/vmlinux`，可以省略 `--btf`：

```bash
sudo tools/deploy_cpa.sh --binary build/bin/cpa
```

如果只写入文件但不启动服务，可以传入 `--no-start`。

脚本会完成这些动作：

- 安装 CPA 到 `/usr/local/lib/cpa/cpa`
- 如果存在 `libgunwinder.so`，安装到 CPA 同目录
- 创建 `/usr/local/bin/cpa` 便捷软链接
- 创建 `/var/log/cpa`
- 写入 `/etc/cpa/cpa.conf`
- 写入 `/etc/systemd/system/cpa.service`
- 执行 `systemctl daemon-reload`
- enable 并启动 `cpa.service`

默认生成的配置：

```text
store_dir: /var/log/cpa
backend: bpf
freq: 49
record_interval: 1
persistent_day: 7
log_print_cycles: 10
record_env_name: POD_NAME,MY_POD_NAME
```

如果传入 `--btf`，脚本会额外写入：

```text
btf_path: /etc/cpa/vmlinux.btf
```

## 卸载

卸载已安装的二进制、软链接、配置文件和 systemd unit，同时保留
`/var/log/cpa` 下的 profiling 数据：

```bash
curl -fsSL https://raw.githubusercontent.com/volcengine/continue-profiling-agent/refs/heads/main/tools/install_cpa.sh | sudo bash -s -- --uninstall
```

如果使用本地 checkout，也可以执行：

```bash
sudo tools/deploy_cpa.sh --uninstall
```

如果需要同时删除 profile 存储目录，追加 `--purge-store`：

```bash
sudo tools/deploy_cpa.sh --uninstall --purge-store
```

## 手动 systemd Service

如果希望自己管理文件，可以把二进制和 shared library 放在同一个目录，创建
`/etc/cpa/cpa.conf`，再使用下面的 unit：

```ini
[Unit]
Description=Continue Profiling Agent
After=local-fs.target
ConditionPathExists=/etc/cpa/cpa.conf

[Service]
Type=simple
WorkingDirectory=/usr/local/lib/cpa
Environment=LD_LIBRARY_PATH=/usr/local/lib/cpa
ExecStart=/usr/local/lib/cpa/cpa monitor --config /etc/cpa/cpa.conf
Restart=always
RestartSec=5s
KillSignal=SIGINT
TimeoutStopSec=30s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

启用服务：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cpa.service
```

## 运维命令

查看状态和日志：

```bash
sudo systemctl status cpa.service
sudo journalctl -u cpa.service -f
```

查看采集结果：

```bash
cpa show --read /var/log/cpa/cpa_YYMMDD --show_range 1
cpa show --read /var/log/cpa/cpa_YYMMDD --output_prof cpa.prof
```

第二条命令在未指定 `--starttime` / `--endtime` 时，会从第一个匹配 record
开始导出。需要指定窗口时，先用 `--show_range` 确认可用时间线。

停止或重启：

```bash
sudo systemctl stop cpa.service
sudo systemctl restart cpa.service
```
